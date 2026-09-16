rule TTP_XOR_WriteProcessMemory_ed23 {
  strings:
    $key_ed23 = { ba 51 [2] 88 73 [2] 8e 46 [2] a0 46 [2] 9f 5a }

  condition:
    any of them
}