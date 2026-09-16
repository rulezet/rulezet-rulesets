rule TTP_XOR_WriteProcessMemory_ed12 {
  strings:
    $key_ed12 = { ba 60 [2] 88 42 [2] 8e 77 [2] a0 77 [2] 9f 6b }

  condition:
    any of them
}