rule TTP_XOR_WriteProcessMemory_7a55 {
  strings:
    $key_7a55 = { 2d 27 [2] 1f 05 [2] 19 30 [2] 37 30 [2] 08 2c }

  condition:
    any of them
}