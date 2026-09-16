rule TTP_XOR_WriteProcessMemory_ed36 {
  strings:
    $key_ed36 = { ba 44 [2] 88 66 [2] 8e 53 [2] a0 53 [2] 9f 4f }

  condition:
    any of them
}