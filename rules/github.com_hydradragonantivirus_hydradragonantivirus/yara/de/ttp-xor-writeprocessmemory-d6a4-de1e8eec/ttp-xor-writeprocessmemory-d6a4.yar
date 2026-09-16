rule TTP_XOR_WriteProcessMemory_d6a4 {
  strings:
    $key_d6a4 = { 81 d6 [2] b3 f4 [2] b5 c1 [2] 9b c1 [2] a4 dd }

  condition:
    any of them
}