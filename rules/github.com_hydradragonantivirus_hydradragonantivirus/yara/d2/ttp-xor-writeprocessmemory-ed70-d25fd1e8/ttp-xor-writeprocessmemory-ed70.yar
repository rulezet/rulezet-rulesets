rule TTP_XOR_WriteProcessMemory_ed70 {
  strings:
    $key_ed70 = { ba 02 [2] 88 20 [2] 8e 15 [2] a0 15 [2] 9f 09 }

  condition:
    any of them
}