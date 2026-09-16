rule TTP_XOR_WriteProcessMemory_ed94 {
  strings:
    $key_ed94 = { ba e6 [2] 88 c4 [2] 8e f1 [2] a0 f1 [2] 9f ed }

  condition:
    any of them
}