rule TTP_XOR_WriteProcessMemory_d0d6 {
  strings:
    $key_d0d6 = { 87 a4 [2] b5 86 [2] b3 b3 [2] 9d b3 [2] a2 af }

  condition:
    any of them
}