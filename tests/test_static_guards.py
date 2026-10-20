from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "main.c").read_text(encoding="utf-8")
SECURITY_HEADER = (ROOT / "ipc_security.h").read_text(encoding="utf-8")
DIRECTORY_NOTIFY_HEADER = (ROOT / "directory_notify.h").read_text(encoding="utf-8")


class IpcHardeningSourceTests(unittest.TestCase):
    def test_pipe_rejects_remote_clients(self):
        self.assertIn("PIPE_REJECT_REMOTE_CLIENTS", SOURCE)

    def test_server_checks_real_client_process_id(self):
        self.assertIn("GetNamedPipeClientProcessId", SOURCE)
        self.assertIn("clientPid != pi.dwProcessId", SOURCE)

    def test_fixed_message_helpers_are_used(self):
        self.assertIn("ReadPipeMessage", SOURCE)
        self.assertIn("WritePipeMessage", SOURCE)
        self.assertIn("ReadPipeStringMessage", SOURCE)

    def test_received_count_is_validated_before_array_read(self):
        count_read = SOURCE.index("ReadPipeMessage(hPipe, &wireCount, (DWORD)sizeof(wireCount))")
        count_guard = SOURCE.index("ipc_valid_point_count(wireCount)", count_read)
        array_read = SOURCE.index("ReadPipeMessage(hPipe, receivedPoints, pointsMessageSize)", count_guard)
        self.assertLess(count_read, count_guard)
        self.assertLess(count_guard, array_read)

    def test_protocol_marker_not_described_as_signature(self):
        self.assertIn("PIPE_PROTOCOL_MAGIC", SOURCE)
        self.assertNotIn("HASH_SIGNATURE", SOURCE)

    def test_failed_login_exits_before_loading_data(self):
        login_guard = SOURCE.index('if (strcmp(in_log, login) != 0)')
        fail_return = SOURCE.index('return 1;', login_guard)
        data_load = SOURCE.index('LoadPointsFromFile("data.txt", pts, &count)')
        self.assertLess(login_guard, fail_return)
        self.assertLess(fail_return, data_load)


    def test_monitor_thread_is_joined_during_cleanup(self):
        self.assertIn("StopAndJoinMonitor(monitorThread)", SOURCE)
        self.assertIn("WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE)", SOURCE)
        self.assertIn("ReadDirectoryChangesW(directory", SOURCE)
        self.assertIn("CancelIoEx(directory, &overlapped)", SOURCE)
        self.assertIn("CloseHandle(directory)", SOURCE)
        self.assertIn("ipc_directory_batch_touches_data_txt(notificationBuffer", SOURCE)
        self.assertNotIn("CloseHandle(monitorThread);", SOURCE)

    def test_monitor_prompt_and_pipe_read_can_be_cancelled(self):
        self.assertIn("ReadMonitorChoice", SOURCE)
        self.assertIn("ReadAnonMessageWithStop", SOURCE)
        self.assertNotIn("ExitProcess(0)", SOURCE)

    def test_parent_runtime_uses_single_cleanup_path(self):
        self.assertIn("parent_cleanup:", SOURCE)
        self.assertIn("CleanupParentRuntime(&monitorThread, &hNamedPipe, &pi)", SOURCE)

    def test_child_listener_waits_for_stop_and_is_joined(self):
        self.assertIn("listenerStopEvent = CreateEventA", SOURCE)
        self.assertIn("WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE)", SOURCE)
        self.assertIn("WaitForSingleObject(listenerThread, INFINITE)", SOURCE)
        self.assertIn("process2_cleanup:", SOURCE)

    def test_file_monitor_filters_for_data_txt(self):
        self.assertIn('CompareStringOrdinal(name, -1, L"data.txt", -1, TRUE)', DIRECTORY_NOTIFY_HEADER)
        self.assertIn("FILE_NOTIFY_CHANGE_FILE_NAME", SOURCE)
        self.assertIn("FILE_NOTIFY_CHANGE_SIZE", SOURCE)

    def test_directory_notification_parser_is_separate_and_used(self):
        self.assertIn("ipc_directory_batch_touches_data_txt", SOURCE)
        self.assertIn("FILE_NOTIFY_INFORMATION", DIRECTORY_NOTIFY_HEADER)
        self.assertIn("CompareStringOrdinal", DIRECTORY_NOTIFY_HEADER)

    def test_sort_checks_allocation_failures(self):
        self.assertIn("if (!ipc_pocket_sort(pts, (size_t)count))", SOURCE)
        self.assertIn("if (node == NULL) return 0;", (ROOT / "pocket_sort.h").read_text(encoding="utf-8"))

    def test_gdi_objects_are_restored_before_deletion(self):
        self.assertGreaterEqual(SOURCE.count("SelectObject(hdc, oldPen)"), 2)
        self.assertIn("SelectObject(hdc, oldBrush)", SOURCE)
        self.assertIn("DeleteObject(axisPen)", SOURCE)
        self.assertIn("DeleteObject(linePen)", SOURCE)
        self.assertIn("DeleteObject(pointBrush)", SOURCE)
        self.assertIn("if (plot_w <= 0 || plot_h <= 0)", SOURCE)

    def test_graph_creation_errors_are_handled(self):
        self.assertIn("if (!RegisterClassA(&wc))", SOURCE)
        self.assertIn("if (hwnd == NULL)", SOURCE)
        self.assertIn("if (getMessageResult == -1)", SOURCE)

    def test_interpolation_uses_separate_checked_numerical_implementation(self):
        self.assertIn('#include "interpolation.h"', SOURCE)
        self.assertIn("ipc_interpolate_point(g_pts", SOURCE)
        self.assertNotIn("double solve_gauss(", SOURCE)
        self.assertIn("if (g_pts[i].x <= g_pts[i - 1].x)", SOURCE)

    def test_graph_skips_unstable_interpolation_samples(self):
        self.assertIn("firstPoint = 1;", SOURCE)
        self.assertIn("!IPC_ISFINITE(real_y)", SOURCE)
        self.assertIn("Ограничивает значение перед преобразованием числа с плавающей точкой в целое", SOURCE)

    def test_console_backspace_is_echoed_as_control_sequence(self):
        self.assertIn(r'printf("\b \b");', SOURCE)

    def test_monitor_strings_use_actual_newline_escapes(self):
        self.assertNotIn(r"printf(\"\\n\")", SOURCE)
        self.assertNotIn(r"\\n", SOURCE[SOURCE.index("static BOOL ReadMonitorChoice"):SOURCE.index("/* Читает файл целиком")])

    def test_named_pipe_uses_explicit_restricted_security_attributes(self):
        self.assertIn("&pipeSecurityAttributes", SOURCE)
        self.assertIn("IpcCreateRestrictedSecurityAttributes", SOURCE)

    def test_named_event_uses_explicit_acl_and_fails_closed_if_preexisting(self):
        self.assertIn("CreateEventA(&eventSecurityAttributes", SOURCE)
        self.assertIn("fileEventCreateStatus == ERROR_ALREADY_EXISTS", SOURCE)

    def test_dacl_is_owner_and_system_only(self):
        self.assertIn('"D:P(A;;GA;;;OW)(A;;GA;;;SY)"', SECURITY_HEADER)
        self.assertNotIn(";;;WD", SECURITY_HEADER)
        self.assertNotIn(";;;AU", SECURITY_HEADER)
        self.assertIn("ConvertStringSecurityDescriptorToSecurityDescriptorA", SECURITY_HEADER)

    def test_ipc_names_are_randomized_per_run(self):
        self.assertIn("BCryptGenRandom", SOURCE)
        self.assertIn("GenerateUniqueIpcNames(pipeName", SOURCE)
        self.assertIn("RunProcess2(hAnonW, argv[3], argv[4])", SOURCE)
        self.assertIn("CreateNamedPipeA(\n            pipeName", SOURCE)

    def test_proc3_requires_the_current_dynamic_pipe_name(self):
        self.assertIn("RunProcess3(argc > 2 ? argv[2] : NULL)", SOURCE)
        self.assertIn("CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE", SOURCE)

    def test_pipe_name_is_regenerated_before_each_creation_and_printed_after(self):
        loop_start = SOURCE.index("while (!pipe_connected && !MonitorStopRequested())")
        regenerate = SOURCE.index("GenerateUniquePipeName(pipeName", loop_start)
        create_pipe = SOURCE.index("CreateNamedPipeA(", regenerate)
        print_name = SOURCE.index("Имя канала текущей попытки", create_pipe)
        self.assertLess(regenerate, create_pipe)
        self.assertLess(create_pipe, print_name)

    def test_named_pipe_requires_first_instance(self):
        create_start = SOURCE.index("CreateNamedPipeA(")
        create_end = SOURCE.index("if (hNamedPipe == INVALID_HANDLE_VALUE)", create_start)
        create_block = SOURCE[create_start:create_end]
        self.assertIn("FILE_FLAG_FIRST_PIPE_INSTANCE", create_block)

if __name__ == "__main__":
    unittest.main()
