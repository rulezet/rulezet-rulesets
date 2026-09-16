rule TTP_XOR_WriteProcessMemory_7ad6 {
  strings:
    $key_7ad6 = { 2d a4 [2] 1f 86 [2] 19 b3 [2] 37 b3 [2] 08 af }

  condition:
    any of them
}