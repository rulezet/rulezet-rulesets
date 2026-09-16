rule TTP_XOR_WriteProcessMemory_e574 {
  strings:
    $key_e574 = { b2 06 [2] 80 24 [2] 86 11 [2] a8 11 [2] 97 0d }

  condition:
    any of them
}