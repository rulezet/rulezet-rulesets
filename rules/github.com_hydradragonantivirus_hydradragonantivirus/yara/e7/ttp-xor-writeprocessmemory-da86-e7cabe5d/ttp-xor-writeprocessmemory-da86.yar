rule TTP_XOR_WriteProcessMemory_da86 {
  strings:
    $key_da86 = { 8d f4 [2] bf d6 [2] b9 e3 [2] 97 e3 [2] a8 ff }

  condition:
    any of them
}