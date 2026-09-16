rule TTP_XOR_WriteProcessMemory_a7b5 {
  strings:
    $key_a7b5 = { f0 c7 [2] c2 e5 [2] c4 d0 [2] ea d0 [2] d5 cc }

  condition:
    any of them
}