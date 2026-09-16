rule TTP_XOR_WriteProcessMemory_0adb {
  strings:
    $key_0adb = { 5d a9 [2] 6f 8b [2] 69 be [2] 47 be [2] 78 a2 }

  condition:
    any of them
}