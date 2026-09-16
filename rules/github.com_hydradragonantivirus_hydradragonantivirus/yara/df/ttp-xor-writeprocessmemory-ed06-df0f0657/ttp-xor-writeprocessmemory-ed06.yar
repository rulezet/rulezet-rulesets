rule TTP_XOR_WriteProcessMemory_ed06 {
  strings:
    $key_ed06 = { ba 74 [2] 88 56 [2] 8e 63 [2] a0 63 [2] 9f 7f }

  condition:
    any of them
}