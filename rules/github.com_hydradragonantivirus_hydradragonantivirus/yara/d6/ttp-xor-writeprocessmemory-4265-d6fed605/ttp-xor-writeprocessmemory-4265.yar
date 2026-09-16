rule TTP_XOR_WriteProcessMemory_4265 {
  strings:
    $key_4265 = { 15 17 [2] 27 35 [2] 21 00 [2] 0f 00 [2] 30 1c }

  condition:
    any of them
}