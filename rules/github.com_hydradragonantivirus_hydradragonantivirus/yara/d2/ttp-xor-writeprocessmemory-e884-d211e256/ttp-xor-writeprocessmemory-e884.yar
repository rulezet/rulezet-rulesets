rule TTP_XOR_WriteProcessMemory_e884 {
  strings:
    $key_e884 = { bf f6 [2] 8d d4 [2] 8b e1 [2] a5 e1 [2] 9a fd }

  condition:
    any of them
}