rule TTP_XOR_WriteProcessMemory_d486 {
  strings:
    $key_d486 = { 83 f4 [2] b1 d6 [2] b7 e3 [2] 99 e3 [2] a6 ff }

  condition:
    any of them
}