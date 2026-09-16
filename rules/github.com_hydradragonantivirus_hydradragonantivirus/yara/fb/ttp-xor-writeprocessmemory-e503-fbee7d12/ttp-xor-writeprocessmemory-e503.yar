rule TTP_XOR_WriteProcessMemory_e503 {
  strings:
    $key_e503 = { b2 71 [2] 80 53 [2] 86 66 [2] a8 66 [2] 97 7a }

  condition:
    any of them
}