rule TTP_XOR_WriteProcessMemory_d4b2 {
  strings:
    $key_d4b2 = { 83 c0 [2] b1 e2 [2] b7 d7 [2] 99 d7 [2] a6 cb }

  condition:
    any of them
}