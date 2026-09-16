rule TTP_XOR_WriteProcessMemory_1adb {
  strings:
    $key_1adb = { 4d a9 [2] 7f 8b [2] 79 be [2] 57 be [2] 68 a2 }

  condition:
    any of them
}