rule TTP_XOR_WriteProcessMemory_f8b0 {
  strings:
    $key_f8b0 = { af c2 [2] 9d e0 [2] 9b d5 [2] b5 d5 [2] 8a c9 }

  condition:
    any of them
}