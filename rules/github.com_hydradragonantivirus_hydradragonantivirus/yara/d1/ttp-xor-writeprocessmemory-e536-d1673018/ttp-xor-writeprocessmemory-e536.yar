rule TTP_XOR_WriteProcessMemory_e536 {
  strings:
    $key_e536 = { b2 44 [2] 80 66 [2] 86 53 [2] a8 53 [2] 97 4f }

  condition:
    any of them
}