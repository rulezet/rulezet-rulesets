rule TTP_XOR_WriteProcessMemory_adb3 {
  strings:
    $key_adb3 = { fa c1 [2] c8 e3 [2] ce d6 [2] e0 d6 [2] df ca }

  condition:
    any of them
}