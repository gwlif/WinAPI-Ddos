#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include "../ipc_validation.h"

static void test_count_boundaries(void)
{
    assert(!ipc_valid_point_count(0));
    assert(!ipc_valid_point_count(1));
    assert(ipc_valid_point_count(2));
    assert(ipc_valid_point_count(IPC_MAX_POINTS));
    assert(!ipc_valid_point_count(IPC_MAX_POINTS + 1u));
    assert(!ipc_valid_point_count(UINT32_MAX));
}

static void test_coordinate_validation(void)
{
    IpcPoint good = { -1000.0, 1000.0 };
    IpcPoint nan_point = { NAN, 0.0 };
    IpcPoint inf_point = { 0.0, INFINITY };
    IpcPoint out_of_range = { 1000.01, 0.0 };

    assert(ipc_valid_point(&good));
    assert(!ipc_valid_point(&nan_point));
    assert(!ipc_valid_point(&inf_point));
    assert(!ipc_valid_point(&out_of_range));
    assert(!ipc_valid_point(NULL));
}

static void test_array_validation(void)
{
    IpcPoint good[] = { {0.0, 1.0}, {1.0, 2.0}, {2.0, 3.0} };
    IpcPoint bad[] = { {0.0, 1.0}, {NAN, 2.0}, {2.0, 3.0} };

    assert(ipc_valid_points(good, 3));
    assert(!ipc_valid_points(bad, 3));
    assert(!ipc_valid_points(good, 1));
    assert(!ipc_valid_points(NULL, 3));
}

static void test_sorted_result_validation(void)
{
    IpcPoint sorted[] = { {-1.0, 0.0}, {0.0, 3.0}, {0.0, 4.0}, {2.0, 1.0} };
    IpcPoint unsorted[] = { {-1.0, 0.0}, {2.0, 3.0}, {0.0, 4.0} };

    assert(ipc_points_sorted_by_x(sorted, 4));
    assert(!ipc_points_sorted_by_x(unsorted, 3));
    assert(!ipc_points_sorted_by_x(NULL, 3));
}

int main(void)
{
    test_count_boundaries();
    test_coordinate_validation();
    test_array_validation();
    test_sorted_result_validation();
    puts("IPC validation tests: OK");
    return 0;
}
