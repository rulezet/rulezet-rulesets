rule TTP_XOR_WriteProcessMemory_62a3 {
  strings:
    $key_62a3 = { 35 d1 [2] 07 f3 [2] 01 c6 [2] 2f c6 [2] 10 da }

  condition:
    any of them
}