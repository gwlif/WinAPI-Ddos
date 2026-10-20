#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../pocket_sort.h"

typedef struct AllocationState {
    size_t calls;
    size_t failAt;
    size_t outstanding;
} AllocationState;

static void *test_allocate(size_t size, void *context)
{
    AllocationState *state = (AllocationState *)context;
    void *pointer;
    size_t call = state->calls++;
    if (call == state->failAt) return NULL;
    pointer = malloc(size);
    if (pointer != NULL) state->outstanding++;
    return pointer;
}

static void test_release(void *pointer, void *context)
{
    AllocationState *state = (AllocationState *)context;
    if (pointer != NULL) {
        assert(state->outstanding > 0);
        state->outstanding--;
        free(pointer);
    }
}

static int is_sorted(const IpcPoint *points, size_t count)
{
    size_t i;
    for (i = 1; i < count; ++i) {
        if (points[i - 1].x > points[i].x) return 0;
    }
    return 1;
}

static void test_sort_success(void)
{
    IpcPoint points[] = { {3.0, 30.0}, {-2.0, 10.0}, {1.0, 20.0}, {0.0, 40.0}, {3.0, 31.0} };
    assert(ipc_pocket_sort(points, sizeof(points) / sizeof(points[0])));
    assert(is_sorted(points, sizeof(points) / sizeof(points[0])));
    assert(points[0].x == -2.0);
    assert(points[4].x == 3.0);
}

static void test_all_equal_x_needs_no_allocation(void)
{
    IpcPoint points[] = { {1.0, 10.0}, {1.0, 20.0}, {1.0, 30.0} };
    AllocationState state = { 0, 0, 0 };
    assert(ipc_pocket_sort_with_allocator(points, 3, test_allocate, test_release, &state));
    assert(state.calls == 0);
    assert(state.outstanding == 0);
}

static void test_every_allocation_failure_cleans_up_and_preserves_input(void)
{
    const IpcPoint original[] = { {3.0, 30.0}, {-2.0, 10.0}, {1.0, 20.0}, {0.0, 40.0} };
    size_t failAt;

    /* Сначала выделяется массив карманов, затем по одному узлу для каждой входной точки. */
    for (failAt = 0; failAt < 1 + sizeof(original) / sizeof(original[0]); ++failAt) {
        IpcPoint points[sizeof(original) / sizeof(original[0])];
        AllocationState state = { 0, failAt, 0 };
        memcpy(points, original, sizeof(original));
        assert(!ipc_pocket_sort_with_allocator(points, sizeof(points) / sizeof(points[0]),
                                               test_allocate, test_release, &state));
        assert(state.outstanding == 0);
        assert(memcmp(points, original, sizeof(original)) == 0);
    }
}

static void test_invalid_inputs_are_rejected(void)
{
    IpcPoint points[] = { {0.0, 0.0}, {1.0, 1.0} };
    assert(!ipc_pocket_sort(NULL, 2));
    assert(!ipc_pocket_sort(points, IPC_MAX_POINTS + 1u));
    points[1].x = 2000.0;
    assert(!ipc_pocket_sort(points, 2));
}

int main(void)
{
    test_sort_success();
    test_all_equal_x_needs_no_allocation();
    test_every_allocation_failure_cleans_up_and_preserves_input();
    test_invalid_inputs_are_rejected();
    puts("Pocket sort tests: OK");
    return 0;
}
