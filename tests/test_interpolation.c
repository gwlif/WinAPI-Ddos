#include <assert.h>
#include <math.h>
#include <stdio.h>
#include "../interpolation.h"

static int close_to(double actual, double expected, double tolerance)
{
    return IPC_ISFINITE(actual) && fabs(actual - expected) <= tolerance;
}

static void test_linear_polynomial(void)
{
    const IpcPoint points[] = {{0.0, 1.0}, {1.0, 3.0}, {2.0, 5.0}, {3.0, 7.0}};
    double y = 0.0;
    assert(ipc_interpolate_point(points, 4u, 1.5, 1, &y));
    assert(close_to(y, 4.0, 1e-10));
}

static void test_quadratic_polynomial(void)
{
    const IpcPoint points[] = {{-2.0, 3.0}, {-1.0, 2.0}, {0.0, 3.0}, {1.0, 6.0}, {2.0, 11.0}};
    double y = 0.0;
    assert(ipc_interpolate_point(points, 5u, 0.5, 2, &y));
    assert(close_to(y, 4.25, 1e-10));
}

static void test_endpoint_values(void)
{
    const IpcPoint points[] = {{-2.0, 4.0}, {-1.0, 1.0}, {0.0, 0.0}, {2.0, 4.0}};
    double y = -1.0;
    assert(ipc_interpolate_point(points, 4u, -2.0, 3, &y));
    assert(close_to(y, 4.0, 1e-10));
    assert(ipc_interpolate_point(points, 4u, 2.0, 3, &y));
    assert(close_to(y, 4.0, 1e-10));
}

static void test_degree_is_limited_to_available_samples(void)
{
    const IpcPoint points[] = {{0.0, 1.0}, {2.0, 5.0}};
    double y = 0.0;
    assert(ipc_interpolate_point(points, 2u, 1.0, 10, &y));
    assert(close_to(y, 3.0, 1e-10));
}

static void test_duplicate_or_unsorted_x_is_rejected(void)
{
    const IpcPoint duplicate[] = {{0.0, 1.0}, {1.0, 2.0}, {1.0, 3.0}};
    const IpcPoint unsorted[] = {{0.0, 1.0}, {2.0, 3.0}, {1.0, 2.0}};
    double y = 99.0;
    assert(!ipc_interpolate_point(duplicate, 3u, 0.5, 1, &y));
    assert(!ipc_interpolate_point(unsorted, 3u, 1.0, 1, &y));
    assert(y == 99.0);
}

static void test_bad_ranges_and_arguments_are_rejected(void)
{
    const IpcPoint points[] = {{0.0, 1.0}, {1.0, 3.0}, {2.0, 5.0}};
    const IpcPoint nonfinite[] = {{0.0, 1.0}, {1.0, INFINITY}};
    double y = 0.0;
    assert(!ipc_interpolate_point(points, 3u, -0.01, 1, &y));
    assert(!ipc_interpolate_point(points, 3u, 2.01, 1, &y));
    assert(!ipc_interpolate_point(points, 3u, NAN, 1, &y));
    assert(!ipc_interpolate_point(points, 1u, 0.0, 1, &y));
    assert(!ipc_interpolate_point(points, 3u, 1.0, 0, &y));
    assert(!ipc_interpolate_point(points, 3u, 1.0, 11, &y));
    assert(!ipc_interpolate_point(nonfinite, 2u, 0.5, 1, &y));
    assert(!ipc_interpolate_point(NULL, 2u, 0.5, 1, &y));
    assert(!ipc_interpolate_point(points, 3u, 0.5, 1, NULL));
}

static void test_extreme_supported_coordinates_stay_finite(void)
{
    const IpcPoint points[] = {{-1000.0, 1.0}, {-500.0, 2.0}, {0.0, 3.0}, {500.0, 4.0}, {1000.0, 5.0}};
    double y = 0.0;
    assert(ipc_interpolate_point(points, 5u, 250.0, 3, &y));
    assert(IPC_ISFINITE(y));
    assert(close_to(y, 3.5, 1e-8));
}

static void test_nearly_singular_window_is_rejected_without_fake_value(void)
{
    const IpcPoint clustered[] = {{0.0, 0.0}, {1e-16, 1.0}, {1.0, 2.0}};
    double y = 123.0;
    assert(!ipc_interpolate_point(clustered, 3u, 0.5, 2, &y));
    assert(y == 123.0);
}

static void test_maximum_degree_with_large_coordinates(void)
{
    const IpcPoint points[] = {
        {-1000.0, 2.0}, {-800.0, 2.4}, {-600.0, 2.8}, {-400.0, 3.2},
        {-200.0, 3.6}, {0.0, 4.0}, {200.0, 4.4}, {400.0, 4.8},
        {600.0, 5.2}, {800.0, 5.6}, {1000.0, 6.0}
    };
    double y = 0.0;
    assert(ipc_interpolate_point(points, 11u, 123.4, 10, &y));
    assert(IPC_ISFINITE(y));
    assert(close_to(y, 4.2468, 1e-7));
}

int main(void)
{
    test_linear_polynomial();
    test_quadratic_polynomial();
    test_endpoint_values();
    test_degree_is_limited_to_available_samples();
    test_duplicate_or_unsorted_x_is_rejected();
    test_bad_ranges_and_arguments_are_rejected();
    test_extreme_supported_coordinates_stay_finite();
    test_nearly_singular_window_is_rejected_without_fake_value();
    test_maximum_degree_with_large_coordinates();
    puts("Interpolation tests: OK");
    return 0;
}
