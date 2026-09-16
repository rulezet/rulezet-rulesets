rule TTP_XOR_WriteProcessMemory_f9a3 {
  strings:
    $key_f9a3 = { ae d1 [2] 9c f3 [2] 9a c6 [2] b4 c6 [2] 8b da }

  condition:
    any of them
}