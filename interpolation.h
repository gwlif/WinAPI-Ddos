#ifndef IPC_INTERPOLATION_H
#define IPC_INTERPOLATION_H

#include <float.h>
#include <math.h>
#include <stddef.h>
#include "ipc_validation.h"

#define IPC_MAX_INTERPOLATION_DEGREE 10u
#define IPC_INTERPOLATION_MAX_TERMS (IPC_MAX_INTERPOLATION_DEGREE + 1u)

/*
 * Решает небольшую плотную систему методом Гаусса с частичным выбором главного элемента.
 * Матрица копируется; исходные массивы A и b вызывающего кода не изменяются.
 * Возвращает 1 только в случае, если удалось вычислить конечное решение.
 */
static inline int ipc_solve_gauss(size_t n,
                                  double a[IPC_INTERPOLATION_MAX_TERMS][IPC_INTERPOLATION_MAX_TERMS],
                                  const double b[IPC_INTERPOLATION_MAX_TERMS],
                                  double x[IPC_INTERPOLATION_MAX_TERMS])
{
    double matrix[IPC_INTERPOLATION_MAX_TERMS][IPC_INTERPOLATION_MAX_TERMS + 1u];
    double matrixScale = 0.0;
    size_t i;
    size_t j;

    if (a == NULL || b == NULL || x == NULL || n == 0u ||
        n > IPC_INTERPOLATION_MAX_TERMS) {
        return 0;
    }

    for (i = 0; i < n; ++i) {
        if (!IPC_ISFINITE(b[i])) return 0;
        for (j = 0; j < n; ++j) {
            double magnitude;
            if (!IPC_ISFINITE(a[i][j])) return 0;
            matrix[i][j] = a[i][j];
            magnitude = fabs(a[i][j]);
            if (magnitude > matrixScale) matrixScale = magnitude;
        }
        matrix[i][n] = b[i];
    }
    if (!IPC_ISFINITE(matrixScale) || matrixScale == 0.0) return 0;

    for (i = 0; i < n; ++i) {
        size_t pivotRow = i;
        double pivotMagnitude = fabs(matrix[i][i]);
        for (j = i + 1u; j < n; ++j) {
            double candidate = fabs(matrix[j][i]);
            if (candidate > pivotMagnitude) {
                pivotMagnitude = candidate;
                pivotRow = j;
            }
        }
        if (!IPC_ISFINITE(pivotMagnitude) ||
            pivotMagnitude <= 128.0 * DBL_EPSILON * matrixScale) {
            return 0;
        }

        if (pivotRow != i) {
            size_t column;
            for (column = i; column <= n; ++column) {
                double temporary = matrix[i][column];
                matrix[i][column] = matrix[pivotRow][column];
                matrix[pivotRow][column] = temporary;
            }
        }

        for (j = i + 1u; j < n; ++j) {
            size_t column;
            double factor = matrix[j][i] / matrix[i][i];
            if (!IPC_ISFINITE(factor)) return 0;
            matrix[j][i] = 0.0;
            for (column = i + 1u; column <= n; ++column) {
                matrix[j][column] -= factor * matrix[i][column];
                if (!IPC_ISFINITE(matrix[j][column])) return 0;
            }
        }
    }

    for (i = n; i-- > 0u;) {
        double value = matrix[i][n];
        for (j = i + 1u; j < n; ++j) {
            value -= matrix[i][j] * x[j];
        }
        if (!IPC_ISFINITE(value) ||
            fabs(matrix[i][i]) <= 128.0 * DBL_EPSILON * matrixScale) {
            return 0;
        }
        x[i] = value / matrix[i][i];
        if (!IPC_ISFINITE(x[i])) return 0;
    }
    return 1;
}

/*
 * Вычисляет значение локального интерполяционного полинома в точке xTarget.
 * Базис полинома масштабируется и центрируется относительно xTarget, поэтому
 * искомое значение совпадает со свободным коэффициентом. Это позволяет избежать
 * больших степеней x вплоть до 1000^10 и заметно улучшает численную устойчивость.
 *
 * Входные данные должны быть конечными, лежать в допустимом диапазоне координат
 * и быть строго отсортированы по X. Повторяющиеся значения X отклоняются, поскольку
 * не задают единственный интерполяционный полином. Экстраполяция не выполняется.
 * Степень уменьшается только в случае, когда доступно недостаточно узлов.
 */
static inline int ipc_interpolate_point(const IpcPoint *points,
                                        size_t totalPoints,
                                        double xTarget,
                                        int degree,
                                        double *outY)
{
    size_t segment = 0u;
    size_t start;
    size_t terms;
    size_t i;
    size_t j;
    double scale = 0.0;
    double matrix[IPC_INTERPOLATION_MAX_TERMS][IPC_INTERPOLATION_MAX_TERMS] = {{0.0}};
    double values[IPC_INTERPOLATION_MAX_TERMS] = {0.0};
    double coefficients[IPC_INTERPOLATION_MAX_TERMS] = {0.0};

    if (points == NULL || outY == NULL || totalPoints < IPC_MIN_POINTS ||
        totalPoints > IPC_MAX_POINTS || degree < 1 ||
        degree > (int)IPC_MAX_INTERPOLATION_DEGREE || !IPC_ISFINITE(xTarget)) {
        return 0;
    }
    if (!ipc_valid_points(points, (uint32_t)totalPoints)) return 0;

    for (i = 1u; i < totalPoints; ++i) {
        if (points[i].x <= points[i - 1u].x) return 0;
    }
    if (xTarget < points[0].x || xTarget > points[totalPoints - 1u].x) return 0;

    if ((size_t)degree >= totalPoints) degree = (int)(totalPoints - 1u);
    terms = (size_t)degree + 1u;

    for (i = 0u; i + 1u < totalPoints; ++i) {
        if (xTarget <= points[i + 1u].x) {
            segment = i;
            break;
        }
    }
    if (segment + 1u >= totalPoints) segment = totalPoints - 2u;

    start = segment;
    if ((size_t)(degree / 2) > start) {
        start = 0u;
    } else {
        start -= (size_t)(degree / 2);
    }
    if (start + terms > totalPoints) start = totalPoints - terms;

    for (i = 0u; i < terms; ++i) {
        double distance = fabs(points[start + i].x - xTarget);
        if (distance > scale) scale = distance;
    }
    if (!IPC_ISFINITE(scale) || scale <= 0.0) return 0;

    for (i = 0u; i < terms; ++i) {
        double normalizedX = (points[start + i].x - xTarget) / scale;
        double power = 1.0;
        if (!IPC_ISFINITE(normalizedX)) return 0;
        values[i] = points[start + i].y;
        for (j = 0u; j < terms; ++j) {
            matrix[i][j] = power;
            power *= normalizedX;
            if (!IPC_ISFINITE(power)) return 0;
        }
    }

    if (!ipc_solve_gauss(terms, matrix, values, coefficients)) return 0;
    if (!IPC_ISFINITE(coefficients[0])) return 0;
    *outY = coefficients[0];
    return 1;
}

#endif /* IPC_INTERPOLATION_H */
