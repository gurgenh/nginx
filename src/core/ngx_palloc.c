
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include <execinfo.h>
#include <stdio.h>
#include <unistd.h>

static ngx_inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size,
    ngx_uint_t align);
static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);
static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);
static void insert_pool(ngx_pool_t* pool);
static void remove_pool(ngx_pool_t* pool);
static void memory_status_printer(int sig);
static void init_signal_handler(int sig);

ngx_pool_list_t* all_pools = NULL;
size_t all_pools_count = 0;
size_t all_pools_size = 0;

FILE* ngx_mem_dbg = 0;

typedef void (*signal_handler_t)(int);
signal_handler_t original_handler = 0;
int signal_initialized = 0;
int current_pid = 0;

void insert_pool(ngx_pool_t* pool) {
  ngx_pool_list_t* new;

  new = (ngx_pool_list_t*)malloc(sizeof(ngx_pool_list_t));
  new->pool = pool;
  new->prev = NULL;
  new->next = NULL;

  ngx_pool_extra(pool)->list = new;

  if (!all_pools) {
    all_pools = new;
  } else {
    all_pools->prev = new;
    new->next = all_pools;
    all_pools = new;
  }
  ++all_pools_count;
}

void remove_pool(ngx_pool_t* pool) {
  ngx_pool_list_t* list;

  list = ngx_pool_extra(pool)->list;
  if (list == all_pools) {
    if (list->next) {
      all_pools = list->next;
    } else {
      all_pools = NULL;
    }
  }

  if (list->prev) {
    list->prev->next = list->next;
  }
  if (list->next) {
    list->next->prev = list->prev;
  }

  free(list);
  --all_pools_count;
}

void ngx_init_mem_debug(void) {
  if (current_pid != 0 && current_pid != getpid()) {
    // forked from master
    current_pid = 0;
    ngx_mem_dbg = 0;
    signal_initialized = 0;
  }
  if (ngx_mem_dbg == 0) {
    current_pid = getpid();
    char file_path[256];
    sprintf(file_path, "/tmp/mem.%d.log", current_pid);
    ngx_mem_dbg = fopen(file_path, "w");
  }
  init_signal_handler(SIGINT);
}

static ngx_inline const char* pool_owner_type(int owner_type) {
  if (owner_type == NGX_POOL_OWNER_CONNECTION) {
    return "ngx_connection_t";
  } else if (owner_type == NGX_POOL_OWNER_REQUEST) {
    return "ngx_http_request_t";
  } else {
    return "void";
  }
}

static void memory_status_printer(int sig) {
  ngx_pool_list_t* list;
  ngx_pool_extra_t* extra;
  MEM_DEBUG("************** NGINX MEMORY STATUS **************\n");
  list = all_pools;
  while (list) {
    extra = ngx_pool_extra(list->pool);
    MEM_DEBUG("* %p -> %zu\n* owner ---> (%s*)(%p)\n* alloc backtrace --->\n",
              list->pool,
              extra->size,
              pool_owner_type(extra->owner.type),
              extra->owner.p);
    fflush(ngx_mem_dbg); // flush as backtrace_symbols_fd uses the fd directly
    backtrace_symbols_fd(extra->bt.trace, extra->bt.size, fileno(ngx_mem_dbg));
    MEM_DEBUG("------------------------------------------------\n");
    list = list->next;
  }

  MEM_DEBUG("**************     POOL SUMMARY    **************\n");
  list = all_pools;
  while (list) {
    extra = ngx_pool_extra(list->pool);
    MEM_DEBUG("* %p -> %zu\n", list->pool, extra->size);
    list = list->next;
  }
  MEM_DEBUG("* overall pools alive      -> %zu\n", all_pools_count);
  MEM_DEBUG("* overall memory allocated -> %zu\n", all_pools_size);
  MEM_DEBUG("****************************************\n");
  fflush(ngx_mem_dbg);
  init_signal_handler(sig);
}

static void init_signal_handler(int sig) {
  signal_handler_t ret;
  ret = signal(sig, memory_status_printer);
  if (!signal_initialized) {
    if (ret == SIG_ERR) {
      MEM_DEBUG("************* FAILED TO INITIALIZE THE SIGNAL %d for %d ******************\n", sig, getpid());
    } else {
      signal_initialized = 1;
      MEM_DEBUG("Signal %d initialized for %d\n", sig, getpid());
      original_handler = ret;
    }
  }
}

ngx_inline ngx_pool_extra_t* ngx_pool_extra(ngx_pool_t* p) {
  return (ngx_pool_extra_t*)(p->extra);
}

ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;
    ngx_pool_extra_t *extra;

    p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(ngx_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(ngx_pool_t);
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    p->extra = malloc(sizeof(ngx_pool_extra_t));
    extra = ngx_pool_extra(p);
    memset(extra, 0, sizeof(ngx_pool_extra_t));
    extra->bt.size = backtrace(extra->bt.trace, sizeof(extra->bt.trace)/sizeof(*extra->bt.trace));

    insert_pool(p);

    MEM_DEBUG("ngx_create_pool: %zu -> %p -- overall %zu\n", size, p, all_pools_count);

    return p;
}


void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    all_pools_size -= ngx_pool_extra(pool)->size;
    remove_pool(pool);
    free(pool->extra);

    MEM_DEBUG("ngx_destroy_pool: %p -- overall %zu\n", pool, all_pools_count);
    MEM_DEBUG("overall memory allocated %zu\n", all_pools_size);

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void
ngx_reset_pool(ngx_pool_t *pool)
{
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(ngx_pool_t);
        p->d.failed = 0;
    }

    MEM_DEBUG("ngx_reset_pool: %p\n", p);

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    MEM_DEBUG("ngx_palloc: %zu from %p\n", size, pool);
    void* p;
    size_t alloc_size;

    ngx_pool_extra(pool)->size += size;
    all_pools_size += size;

    MEM_DEBUG("pool size %zu, overall memory allocated %zu\n", ngx_pool_extra(pool)->size, all_pools_size);

    alloc_size = size + sizeof(size_t);

#if !(NGX_DEBUG_PALLOC)
    if (alloc_size <= pool->max) {
        p = ngx_palloc_small(pool, alloc_size, 1);
        *(size_t*)p = size;
        p = (size_t*)p + 1;

        MEM_DEBUG("ngx_palloc: %zu from %p -> %p\n", size, pool, p);
        return p;
    }
#endif

    p = ngx_palloc_large(pool, alloc_size);
    *(size_t*)p = size;
    p = (size_t*)p + 1;
    MEM_DEBUG("ngx_palloc: %zu from %p -> %p\n", size, pool, p);
    return p;
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    MEM_DEBUG("ngx_palloc: %zu from %p\n", size, pool);
    void* p;
    size_t alloc_size;

    ngx_pool_extra(pool)->size += size;
    all_pools_size += size;

    MEM_DEBUG("pool size %zu, overall memory allocated %zu\n", ngx_pool_extra(pool)->size, all_pools_size);

    alloc_size = size + sizeof(size_t);

#if !(NGX_DEBUG_PALLOC)
    if (alloc_size <= pool->max) {
        p = ngx_palloc_small(pool, alloc_size, 0);
        *(size_t*)p = size;
        p = (size_t*)p + 1;

        MEM_DEBUG("ngx_palloc: %zu from %p -> %p\n", size, pool, p);
        return p;
    }
#endif

    p = ngx_palloc_large(pool, alloc_size);
    *(size_t*)p = size;
    p = (size_t*)p + 1;

    MEM_DEBUG("ngx_palloc: %zu from %p -> %p\n", size, pool, p);
    return p;
}


static ngx_inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
{
    u_char      *m;
    ngx_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = ngx_align_ptr(m, NGX_ALIGNMENT);
        }

        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return ngx_palloc_block(pool, size);
}


static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    ngx_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    new = (ngx_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(ngx_pool_data_t);
    m = ngx_align_ptr(m, NGX_ALIGNMENT);
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}


static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    ngx_uint_t         n;
    ngx_pool_large_t  *large;

    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    ngx_pool_large_t  *large;

    p = ngx_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;
    size_t size;

    p = (size_t*)p - 1;
    size = *(size_t*)p;
    ngx_pool_extra(pool)->size -= size;
    all_pools_size -= size;

    MEM_DEBUG("ngx_pfree %p of size %zu from %p\n", p, size, pool);
    MEM_DEBUG("pool size %zu, overall memory allocated %zu\n", ngx_pool_extra(pool)->size, all_pools_size);

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd)
{
    ngx_pool_cleanup_t       *c;
    ngx_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == ngx_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


void
ngx_pool_delete_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_err_t  err;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                          ngx_delete_file_n " \"%s\" failed", c->name);
        }
    }

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
