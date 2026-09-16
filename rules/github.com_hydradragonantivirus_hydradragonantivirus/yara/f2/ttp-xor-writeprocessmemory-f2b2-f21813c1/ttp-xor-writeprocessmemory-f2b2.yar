rule TTP_XOR_WriteProcessMemory_f2b2 {
  strings:
    $key_f2b2 = { a5 c0 [2] 97 e2 [2] 91 d7 [2] bf d7 [2] 80 cb }

  condition:
    any of them
}