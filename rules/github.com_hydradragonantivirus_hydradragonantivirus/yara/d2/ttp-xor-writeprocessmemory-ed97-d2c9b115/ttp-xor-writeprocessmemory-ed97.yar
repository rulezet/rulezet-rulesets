rule TTP_XOR_WriteProcessMemory_ed97 {
  strings:
    $key_ed97 = { ba e5 [2] 88 c7 [2] 8e f2 [2] a0 f2 [2] 9f ee }

  condition:
    any of them
}