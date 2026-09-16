rule TTP_XOR_WriteProcessMemory_adb6 {
  strings:
    $key_adb6 = { fa c4 [2] c8 e6 [2] ce d3 [2] e0 d3 [2] df cf }

  condition:
    any of them
}