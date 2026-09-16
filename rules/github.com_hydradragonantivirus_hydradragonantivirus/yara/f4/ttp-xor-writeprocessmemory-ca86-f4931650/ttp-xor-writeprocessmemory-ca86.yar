rule TTP_XOR_WriteProcessMemory_ca86 {
  strings:
    $key_ca86 = { 9d f4 [2] af d6 [2] a9 e3 [2] 87 e3 [2] b8 ff }

  condition:
    any of them
}