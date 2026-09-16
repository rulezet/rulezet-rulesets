rule TTP_XOR_WriteProcessMemory_7ad1 {
  strings:
    $key_7ad1 = { 2d a3 [2] 1f 81 [2] 19 b4 [2] 37 b4 [2] 08 a8 }

  condition:
    any of them
}