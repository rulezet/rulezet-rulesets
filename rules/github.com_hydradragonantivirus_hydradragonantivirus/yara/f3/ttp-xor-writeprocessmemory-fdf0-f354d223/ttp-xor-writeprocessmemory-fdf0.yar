rule TTP_XOR_WriteProcessMemory_fdf0 {
  strings:
    $key_fdf0 = { aa 82 [2] 98 a0 [2] 9e 95 [2] b0 95 [2] 8f 89 }

  condition:
    any of them
}