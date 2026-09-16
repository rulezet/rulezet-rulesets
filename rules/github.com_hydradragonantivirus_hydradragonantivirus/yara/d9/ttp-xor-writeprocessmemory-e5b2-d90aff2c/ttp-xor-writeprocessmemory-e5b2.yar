rule TTP_XOR_WriteProcessMemory_e5b2 {
  strings:
    $key_e5b2 = { b2 c0 [2] 80 e2 [2] 86 d7 [2] a8 d7 [2] 97 cb }

  condition:
    any of them
}