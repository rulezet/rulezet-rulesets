rule TTP_XOR_WriteProcessMemory_ed26 {
  strings:
    $key_ed26 = { ba 54 [2] 88 76 [2] 8e 43 [2] a0 43 [2] 9f 5f }

  condition:
    any of them
}