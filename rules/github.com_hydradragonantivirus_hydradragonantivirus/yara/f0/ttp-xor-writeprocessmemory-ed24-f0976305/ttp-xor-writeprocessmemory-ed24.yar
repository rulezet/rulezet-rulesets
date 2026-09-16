rule TTP_XOR_WriteProcessMemory_ed24 {
  strings:
    $key_ed24 = { ba 56 [2] 88 74 [2] 8e 41 [2] a0 41 [2] 9f 5d }

  condition:
    any of them
}