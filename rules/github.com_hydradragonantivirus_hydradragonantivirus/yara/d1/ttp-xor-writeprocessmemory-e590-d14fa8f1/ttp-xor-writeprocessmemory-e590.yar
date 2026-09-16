rule TTP_XOR_WriteProcessMemory_e590 {
  strings:
    $key_e590 = { b2 e2 [2] 80 c0 [2] 86 f5 [2] a8 f5 [2] 97 e9 }

  condition:
    any of them
}