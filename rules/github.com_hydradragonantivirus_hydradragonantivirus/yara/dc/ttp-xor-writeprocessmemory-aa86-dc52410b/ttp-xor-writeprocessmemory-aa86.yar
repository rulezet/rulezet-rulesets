rule TTP_XOR_WriteProcessMemory_aa86 {
  strings:
    $key_aa86 = { fd f4 [2] cf d6 [2] c9 e3 [2] e7 e3 [2] d8 ff }

  condition:
    any of them
}