rule TTP_XOR_WriteProcessMemory_ed41 {
  strings:
    $key_ed41 = { ba 33 [2] 88 11 [2] 8e 24 [2] a0 24 [2] 9f 38 }

  condition:
    any of them
}