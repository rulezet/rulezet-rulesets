rule TTP_XOR_WriteProcessMemory_a786 {
  strings:
    $key_a786 = { f0 f4 [2] c2 d6 [2] c4 e3 [2] ea e3 [2] d5 ff }

  condition:
    any of them
}