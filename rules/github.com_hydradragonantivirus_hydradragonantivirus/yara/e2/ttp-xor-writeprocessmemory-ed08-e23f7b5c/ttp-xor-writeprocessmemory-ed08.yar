rule TTP_XOR_WriteProcessMemory_ed08 {
  strings:
    $key_ed08 = { ba 7a [2] 88 58 [2] 8e 6d [2] a0 6d [2] 9f 71 }

  condition:
    any of them
}