rule TTP_XOR_WriteProcessMemory_ecf2 {
  strings:
    $key_ecf2 = { bb 80 [2] 89 a2 [2] 8f 97 [2] a1 97 [2] 9e 8b }

  condition:
    any of them
}