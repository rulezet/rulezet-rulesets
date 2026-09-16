rule TTP_XOR_WriteProcessMemory_f9a6 {
  strings:
    $key_f9a6 = { ae d4 [2] 9c f6 [2] 9a c3 [2] b4 c3 [2] 8b df }

  condition:
    any of them
}