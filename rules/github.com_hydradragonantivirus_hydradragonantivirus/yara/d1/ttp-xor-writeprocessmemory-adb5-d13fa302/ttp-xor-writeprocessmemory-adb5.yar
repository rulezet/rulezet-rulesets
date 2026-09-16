rule TTP_XOR_WriteProcessMemory_adb5 {
  strings:
    $key_adb5 = { fa c7 [2] c8 e5 [2] ce d0 [2] e0 d0 [2] df cc }

  condition:
    any of them
}