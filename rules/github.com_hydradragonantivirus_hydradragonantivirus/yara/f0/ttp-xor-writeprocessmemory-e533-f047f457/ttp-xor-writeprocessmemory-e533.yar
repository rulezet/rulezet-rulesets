rule TTP_XOR_WriteProcessMemory_e533 {
  strings:
    $key_e533 = { b2 41 [2] 80 63 [2] 86 56 [2] a8 56 [2] 97 4a }

  condition:
    any of them
}