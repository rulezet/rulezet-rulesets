rule TTP_XOR_WriteProcessMemory_fdb2 {
  strings:
    $key_fdb2 = { aa c0 [2] 98 e2 [2] 9e d7 [2] b0 d7 [2] 8f cb }

  condition:
    any of them
}