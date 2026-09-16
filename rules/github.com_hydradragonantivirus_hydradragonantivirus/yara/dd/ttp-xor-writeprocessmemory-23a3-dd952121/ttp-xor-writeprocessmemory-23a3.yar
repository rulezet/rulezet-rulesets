rule TTP_XOR_WriteProcessMemory_23a3 {
  strings:
    $key_23a3 = { 74 d1 [2] 46 f3 [2] 40 c6 [2] 6e c6 [2] 51 da }

  condition:
    any of them
}