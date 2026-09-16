rule TTP_XOR_WriteProcessMemory_3d06 {
  strings:
    $key_3d06 = { 6a 74 [2] 58 56 [2] 5e 63 [2] 70 63 [2] 4f 7f }

  condition:
    any of them
}