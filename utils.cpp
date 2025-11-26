#include "utils.hpp"
#include <string>
#include <Windows.h>

bool utils::DevicePathToDosPath(const char *devicePath, char *dosPath, size_t dosPathSize)
{
    char drive[3] = "A:";
    char driveLetter[4];
    char deviceName[MAX_PATH];
    char path[MAX_PATH];

    for (char letter = 'A'; letter <= 'Z'; ++letter)
    {
        drive[0] = letter;
        if (QueryDosDeviceA(drive, deviceName, MAX_PATH))
        {
            size_t len = strlen(deviceName);
            if (len < MAX_PATH && _strnicmp(devicePath, deviceName, len) == 0)
            {
                snprintf(dosPath, dosPathSize, "%c:%s", letter, devicePath + len);
                return TRUE;
            }
        }
    }
    return FALSE;
}

void utils::swap(const char **a, const char **b)
{
    const char *temp = *a;
    *a = *b;
    *b = temp;
}

void utils::shuffle(const char **arr, size_t n)
{
    for (size_t i = n - 1; i > 0; --i)
    {
        size_t j = rand() % (i + 1);
        swap(&arr[i], &arr[j]);
    }
}