wchar_t exePath[MAX_PATH];
GetModuleFileNameW(NULL, exePath, MAX_PATH);
std::wstring path(exePath);
size_t lastDot = path.find_last_of(L".");
if (lastDot != std::wstring::npos) path = path.substr(0, lastDot);
path += L".ini";

ParseIniFile(path);

printf("--- Starting Main Loop ---\n");

std::thread t1(ForegroundBoosterThread);
std::thread t2(DwmThread);
t1.join();
t2.join();
return 0;