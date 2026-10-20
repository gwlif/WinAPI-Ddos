#ifndef POCKET_SORT_H
#define POCKET_SORT_H

#include <stddef.h>
#include <stdlib.h>
#include "ipc_validation.h"

typedef void *(*IpcSortAllocate)(size_t size, void *context);
typedef void (*IpcSortRelease)(void *pointer, void *context);

typedef struct IpcSortNode {
    IpcPoint point;
    struct IpcSortNode *next;
} IpcSortNode;

typedef struct IpcSortBucket {
    IpcSortNode *head;
    IpcSortNode *tail;
} IpcSortBucket;

static inline void *ipc_sort_default_allocate(size_t size, void *context)
{
    (void)context;
    return malloc(size);
}

static inline void ipc_sort_default_release(void *pointer, void *context)
{
    (void)context;
    free(pointer);
}

static inline void ipc_sort_clear_bucket(IpcSortBucket *bucket,
                                         IpcSortRelease release,
                                         void *context)
{
    IpcSortNode *node;
    if (bucket == NULL || release == NULL) return;
    node = bucket->head;
    while (node != NULL) {
        IpcSortNode *next = node->next;
        release(node, context);
        node = next;
    }
    bucket->head = NULL;
    bucket->tail = NULL;
}

static inline int ipc_sort_enqueue(IpcSortBucket *bucket, IpcPoint point,
                                   IpcSortAllocate allocate, void *context)
{
    IpcSortNode *node;
    IpcSortNode *current;

    if (bucket == NULL || allocate == NULL) return 0;
    node = (IpcSortNode *)allocate(sizeof(*node), context);
    if (node == NULL) return 0;
    node->point = point;
    node->next = NULL;

    if (bucket->head == NULL || bucket->head->point.x >= point.x) {
        node->next = bucket->head;
        bucket->head = node;
        if (bucket->tail == NULL) bucket->tail = node;
        return 1;
    }

    current = bucket->head;
    while (current->next != NULL && current->next->point.x < point.x) {
        current = current->next;
    }
    node->next = current->next;
    current->next = node;
    if (node->next == NULL) bucket->tail = node;
    return 1;
}

/*
 * Исходный массив не изменяется при ошибке любого выделения памяти. Передаваемые
 * функции выделения и освобождения позволяют детерминированно имитировать отказ
 * каждого выделения в тестах, не исчерпывая настоящую системную память.
 */
static inline int ipc_pocket_sort_with_allocator(IpcPoint *points, size_t count,
                                                  IpcSortAllocate allocate,
                                                  IpcSortRelease release,
                                                  void *context)
{
    IpcSortBucket *buckets;
    double minX;
    double maxX;
    size_t i;
    size_t bucketCount;
    size_t outputIndex = 0;

    if (points == NULL || allocate == NULL || release == NULL || count > IPC_MAX_POINTS) {
        return 0;
    }
    if (count <= 1) return 1;
    if (!ipc_valid_points(points, (uint32_t)count)) return 0;

    minX = points[0].x;
    maxX = points[0].x;
    for (i = 1; i < count; ++i) {
        if (points[i].x < minX) minX = points[i].x;
        if (points[i].x > maxX) maxX = points[i].x;
    }
    if (maxX == minX) return 1;

    bucketCount = count;
    if (bucketCount > ((size_t)-1) / sizeof(*buckets)) return 0;
    buckets = (IpcSortBucket *)allocate(bucketCount * sizeof(*buckets), context);
    if (buckets == NULL) return 0;
    for (i = 0; i < bucketCount; ++i) {
        buckets[i].head = NULL;
        buckets[i].tail = NULL;
    }

    for (i = 0; i < count; ++i) {
        double scaled = ((points[i].x - minX) / (maxX - minX)) * (double)(bucketCount - 1);
        size_t index = (size_t)scaled;
        if (index >= bucketCount) index = bucketCount - 1;
        if (!ipc_sort_enqueue(&buckets[index], points[i], allocate, context)) {
            size_t cleanupIndex;
            for (cleanupIndex = 0; cleanupIndex < bucketCount; ++cleanupIndex) {
                ipc_sort_clear_bucket(&buckets[cleanupIndex], release, context);
            }
            release(buckets, context);
            return 0;
        }
    }

    for (i = 0; i < bucketCount; ++i) {
        IpcSortNode *node = buckets[i].head;
        while (node != NULL) {
            IpcSortNode *next = node->next;
            points[outputIndex++] = node->point;
            release(node, context);
            node = next;
        }
        buckets[i].head = NULL;
        buckets[i].tail = NULL;
    }
    release(buckets, context);
    return outputIndex == count;
}

static inline int ipc_pocket_sort(IpcPoint *points, size_t count)
{
    return ipc_pocket_sort_with_allocator(points, count,
                                           ipc_sort_default_allocate,
                                           ipc_sort_default_release,
                                           NULL);
}

#endif /* POCKET_SORT_H */
