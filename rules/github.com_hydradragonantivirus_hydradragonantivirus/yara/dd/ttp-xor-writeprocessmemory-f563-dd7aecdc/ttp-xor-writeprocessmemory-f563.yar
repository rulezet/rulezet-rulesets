rule TTP_XOR_WriteProcessMemory_f563 {
  strings:
    $key_f563 = { a2 11 [2] 90 33 [2] 96 06 [2] b8 06 [2] 87 1a }

  condition:
    any of them
}