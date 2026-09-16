rule TTP_XOR_WriteProcessMemory_d386 {
  strings:
    $key_d386 = { 84 f4 [2] b6 d6 [2] b0 e3 [2] 9e e3 [2] a1 ff }

  condition:
    any of them
}