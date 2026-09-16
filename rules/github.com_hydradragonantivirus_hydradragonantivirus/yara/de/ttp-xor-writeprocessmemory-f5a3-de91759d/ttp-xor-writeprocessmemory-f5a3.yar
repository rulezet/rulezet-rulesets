rule TTP_XOR_WriteProcessMemory_f5a3 {
  strings:
    $key_f5a3 = { a2 d1 [2] 90 f3 [2] 96 c6 [2] b8 c6 [2] 87 da }

  condition:
    any of them
}