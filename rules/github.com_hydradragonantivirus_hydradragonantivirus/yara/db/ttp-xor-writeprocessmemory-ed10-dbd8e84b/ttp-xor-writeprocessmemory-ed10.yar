rule TTP_XOR_WriteProcessMemory_ed10 {
  strings:
    $key_ed10 = { ba 62 [2] 88 40 [2] 8e 75 [2] a0 75 [2] 9f 69 }

  condition:
    any of them
}