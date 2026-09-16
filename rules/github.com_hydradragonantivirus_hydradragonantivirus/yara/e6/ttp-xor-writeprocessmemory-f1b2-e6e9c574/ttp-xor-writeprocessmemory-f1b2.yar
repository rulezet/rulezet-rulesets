rule TTP_XOR_WriteProcessMemory_f1b2 {
  strings:
    $key_f1b2 = { a6 c0 [2] 94 e2 [2] 92 d7 [2] bc d7 [2] 83 cb }

  condition:
    any of them
}