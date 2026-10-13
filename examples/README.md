# Mock target

The mock target publishes one binary result at a time. It writes to a temporary
file and renames it into place so the runtime never observes a partially
published record.

```powershell
g++ -std=c++11 -O2 mock_target_app.cpp -o mock_target_app.exe
.\mock_target_app.exe --interval 3 --output output
```

MSVC:

```powershell
cl /std:c++11 /EHsc mock_target_app.cpp
mock_target_app.exe --interval 3 --output output
```

The matching driver is `../drivers/templates/sample_driver.yaml`.

