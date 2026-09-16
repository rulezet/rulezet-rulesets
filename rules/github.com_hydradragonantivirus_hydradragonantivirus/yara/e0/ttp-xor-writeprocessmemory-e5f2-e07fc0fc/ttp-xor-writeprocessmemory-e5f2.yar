rule TTP_XOR_WriteProcessMemory_e5f2 {
  strings:
    $key_e5f2 = { b2 80 [2] 80 a2 [2] 86 97 [2] a8 97 [2] 97 8b }

  condition:
    any of them
}