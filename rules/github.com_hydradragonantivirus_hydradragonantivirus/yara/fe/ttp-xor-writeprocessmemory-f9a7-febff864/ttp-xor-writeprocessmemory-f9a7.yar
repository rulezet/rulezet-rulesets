rule TTP_XOR_WriteProcessMemory_f9a7 {
  strings:
    $key_f9a7 = { ae d5 [2] 9c f7 [2] 9a c2 [2] b4 c2 [2] 8b de }

  condition:
    any of them
}