rule TTP_XOR_WriteProcessMemory_75a3 {
  strings:
    $key_75a3 = { 22 d1 [2] 10 f3 [2] 16 c6 [2] 38 c6 [2] 07 da }

  condition:
    any of them
}