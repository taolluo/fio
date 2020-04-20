//
// Created by taolluo on 4/3/20.
//

#ifndef FIO_IO_URING_H
#define FIO_IO_URING_H


struct io_sq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    unsigned *flags;
    unsigned *array;
};

struct io_cq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    struct io_uring_cqe *cqes;
};

struct ioring_mmap {
    void *ptr;
    size_t len;
};

struct ioring_data {
    int ring_fd;

    struct io_u **io_u_index;

    int *fds;

    struct io_sq_ring sq_ring;
    struct io_uring_sqe *sqes;
    struct iovec *iovecs;
    unsigned sq_ring_mask;
    unsigned sq_entries;
    unsigned cq_entries;
    struct io_cq_ring cq_ring;
    unsigned cq_ring_mask;

    int queued;
    int cq_ring_off;
    unsigned iodepth;
    bool ioprio_class_set;
    bool ioprio_set;

    struct ioring_mmap mmap[3];
};

struct ioring_options {
    void *pad;
    unsigned int hipri;
    unsigned int cmdprio_percentage;
    unsigned int fixedbufs;
    unsigned int registerfiles;
    unsigned int sqpoll_thread;
    unsigned int sqpoll_set;
    unsigned int sqpoll_cpu;
    unsigned int sqpoll_idle_set;
    unsigned int sqpoll_idle;
    unsigned int nonvectored;
    unsigned int uncached;
};

#endif //FIO_IO_URING_H