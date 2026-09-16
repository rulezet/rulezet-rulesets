rule TTP_XOR_WriteProcessMemory_d086 {
  strings:
    $key_d086 = { 87 f4 [2] b5 d6 [2] b3 e3 [2] 9d e3 [2] a2 ff }

  condition:
    any of them
}