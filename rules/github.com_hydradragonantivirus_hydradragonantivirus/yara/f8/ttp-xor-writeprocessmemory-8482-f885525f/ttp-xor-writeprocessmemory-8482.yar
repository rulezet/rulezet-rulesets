rule TTP_XOR_WriteProcessMemory_8482 {
  strings:
    $key_8482 = { d3 f0 [2] e1 d2 [2] e7 e7 [2] c9 e7 [2] f6 fb }

  condition:
    any of them
}