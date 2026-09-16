rule TTP_XOR_WriteProcessMemory_c7b2 {
  strings:
    $key_c7b2 = { 90 c0 [2] a2 e2 [2] a4 d7 [2] 8a d7 [2] b5 cb }

  condition:
    any of them
}