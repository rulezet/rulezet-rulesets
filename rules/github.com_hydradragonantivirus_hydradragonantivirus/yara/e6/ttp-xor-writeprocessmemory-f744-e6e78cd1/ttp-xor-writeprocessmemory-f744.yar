rule TTP_XOR_WriteProcessMemory_f744 {
  strings:
    $key_f744 = { a0 36 [2] 92 14 [2] 94 21 [2] ba 21 [2] 85 3d }

  condition:
    any of them
}