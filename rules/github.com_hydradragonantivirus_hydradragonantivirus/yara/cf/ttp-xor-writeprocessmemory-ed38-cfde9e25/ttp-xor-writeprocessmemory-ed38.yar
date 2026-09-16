rule TTP_XOR_WriteProcessMemory_ed38 {
  strings:
    $key_ed38 = { ba 4a [2] 88 68 [2] 8e 5d [2] a0 5d [2] 9f 41 }

  condition:
    any of them
}