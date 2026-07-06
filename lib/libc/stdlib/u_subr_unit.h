struct unrhdr;
struct mtx;
struct unr;

/* Global shared state for cheri otypes across all allocators */
extern struct unrhdr* cheri_otypes_ptr;
extern struct unrhdr cheri_otypes;
extern void* global_sealing_bitmap;
extern int global_sealing_bitmap_size;
extern bool global_cheri_otypes_initialized;
extern struct cheri_revoke_info *cri;
/* Get or initialize the global cheri_otypes allocator */
struct unrhdr* get_global_cheri_otypes(void);
/* Get or initialize the global sealing bitmap */
void* get_global_sealing_bitmap(int* size_out);

#define CC_DEBUG 0

struct lb_window{
    struct unr* back_pointer;
    struct unr* fowards_pointer;
    int len;
    int alloc_count;
};

#define	UNR_NO_MTX	((void *)(uintptr_t)-1)
struct unrhdr *new_unrhdr(int low, int high, struct mtx *mutex);

void init_unrhdr(struct unrhdr *uh, int low, int high, struct mtx *mutex);
void delete_unrhdr(struct unrhdr *uh);
void clear_unrhdr(struct unrhdr *uh);
void clean_unrhdr(struct unrhdr *uh);
void clean_unrhdrl(struct unrhdr *uh);
int alloc_unr(struct unrhdr *uh);
int alloc_unr_specific(struct unrhdr *uh, u_int item);
int alloc_unrl(struct unrhdr *uh);
void free_unr(struct unrhdr *uh, u_int item);
void *create_iter_unr(struct unrhdr *uh);
int next_iter_unr(void *handle);
void free_iter_unr(void *handle);
void free_many_unr(struct unrhdr** uh, u_int64_t* sealing_bitmap, int should_free_old_uh);
void* mrs_calloc_unr(size_t number, size_t size);
void printf_uh(struct unrhdr* uh);
void print_diff_from_iters(struct unrhdr *uh1, struct unrhdr *uh2);
inline void check_unrhdr(struct unrhdr *uh, int line);
void copy_unrhdr(struct unrhdr *old_uh, struct unrhdr *new_uh);