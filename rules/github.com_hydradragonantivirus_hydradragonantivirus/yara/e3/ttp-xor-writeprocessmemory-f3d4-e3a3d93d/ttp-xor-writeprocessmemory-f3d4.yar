rule TTP_XOR_WriteProcessMemory_f3d4 {
  strings:
    $key_f3d4 = { a4 a6 [2] 96 84 [2] 90 b1 [2] be b1 [2] 81 ad }

  condition:
    any of them
}