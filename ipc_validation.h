#ifndef IPC_VALIDATION_H
#define IPC_VALIDATION_H

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <float.h>
#define IPC_ISFINITE(value) (_finite(value) != 0)
#else
#define IPC_ISFINITE(value) isfinite(value)
#endif

#define IPC_MAX_POINTS 100u
#define IPC_MIN_POINTS 2u
#define IPC_COORD_MIN (-1000.0)
#define IPC_COORD_MAX (1000.0)

typedef struct IpcPoint {
    double x;
    double y;
} IpcPoint;

static inline int ipc_valid_point_count(uint32_t count)
{
    return count >= IPC_MIN_POINTS && count <= IPC_MAX_POINTS;
}

static inline int ipc_valid_point(const IpcPoint *point)
{
    return point != NULL &&
           IPC_ISFINITE(point->x) && IPC_ISFINITE(point->y) &&
           point->x >= IPC_COORD_MIN && point->x <= IPC_COORD_MAX &&
           point->y >= IPC_COORD_MIN && point->y <= IPC_COORD_MAX;
}

static inline int ipc_valid_points(const IpcPoint *points, uint32_t count)
{
    uint32_t i;

    if (points == NULL || !ipc_valid_point_count(count)) {
        return 0;
    }

    for (i = 0; i < count; ++i) {
        if (!ipc_valid_point(&points[i])) {
            return 0;
        }
    }
    return 1;
}

static inline int ipc_points_sorted_by_x(const IpcPoint *points, uint32_t count)
{
    uint32_t i;

    if (points == NULL || !ipc_valid_point_count(count)) {
        return 0;
    }

    for (i = 1; i < count; ++i) {
        if (points[i - 1].x > points[i].x) {
            return 0;
        }
    }
    return 1;
}

#endif /* IPC_VALIDATION_H */
