rule TTP_XOR_WriteProcessMemory_00a3 {
  strings:
    $key_00a3 = { 57 d1 [2] 65 f3 [2] 63 c6 [2] 4d c6 [2] 72 da }

  condition:
    any of them
}