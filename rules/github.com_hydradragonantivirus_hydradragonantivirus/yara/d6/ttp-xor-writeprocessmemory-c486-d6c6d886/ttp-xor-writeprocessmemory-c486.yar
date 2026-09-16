rule TTP_XOR_WriteProcessMemory_c486 {
  strings:
    $key_c486 = { 93 f4 [2] a1 d6 [2] a7 e3 [2] 89 e3 [2] b6 ff }

  condition:
    any of them
}