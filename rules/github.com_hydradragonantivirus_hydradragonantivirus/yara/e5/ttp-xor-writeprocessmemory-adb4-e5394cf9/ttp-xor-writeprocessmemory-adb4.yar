rule TTP_XOR_WriteProcessMemory_adb4 {
  strings:
    $key_adb4 = { fa c6 [2] c8 e4 [2] ce d1 [2] e0 d1 [2] df cd }

  condition:
    any of them
}