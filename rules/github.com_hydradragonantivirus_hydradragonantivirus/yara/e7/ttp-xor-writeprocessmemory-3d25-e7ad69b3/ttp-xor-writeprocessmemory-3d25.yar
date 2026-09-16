rule TTP_XOR_WriteProcessMemory_3d25 {
  strings:
    $key_3d25 = { 6a 57 [2] 58 75 [2] 5e 40 [2] 70 40 [2] 4f 5c }

  condition:
    any of them
}