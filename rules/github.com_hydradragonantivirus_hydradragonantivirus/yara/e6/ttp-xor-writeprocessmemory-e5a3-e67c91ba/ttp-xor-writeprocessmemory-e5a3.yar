rule TTP_XOR_WriteProcessMemory_e5a3 {
  strings:
    $key_e5a3 = { b2 d1 [2] 80 f3 [2] 86 c6 [2] a8 c6 [2] 97 da }

  condition:
    any of them
}