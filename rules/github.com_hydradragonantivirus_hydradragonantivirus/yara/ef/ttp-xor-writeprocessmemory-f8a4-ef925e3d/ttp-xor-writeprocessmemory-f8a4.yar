rule TTP_XOR_WriteProcessMemory_f8a4 {
  strings:
    $key_f8a4 = { af d6 [2] 9d f4 [2] 9b c1 [2] b5 c1 [2] 8a dd }

  condition:
    any of them
}