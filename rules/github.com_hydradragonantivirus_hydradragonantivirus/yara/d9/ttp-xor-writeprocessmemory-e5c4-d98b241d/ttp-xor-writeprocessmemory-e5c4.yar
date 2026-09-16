rule TTP_XOR_WriteProcessMemory_e5c4 {
  strings:
    $key_e5c4 = { b2 b6 [2] 80 94 [2] 86 a1 [2] a8 a1 [2] 97 bd }

  condition:
    any of them
}