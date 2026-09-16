rule TTP_XOR_WriteProcessMemory_46a3 {
  strings:
    $key_46a3 = { 11 d1 [2] 23 f3 [2] 25 c6 [2] 0b c6 [2] 34 da }

  condition:
    any of them
}