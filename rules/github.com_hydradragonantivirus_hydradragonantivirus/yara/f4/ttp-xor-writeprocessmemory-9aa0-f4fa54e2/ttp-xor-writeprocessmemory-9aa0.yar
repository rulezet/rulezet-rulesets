rule TTP_XOR_WriteProcessMemory_9aa0 {
  strings:
    $key_9aa0 = { cd d2 [2] ff f0 [2] f9 c5 [2] d7 c5 [2] e8 d9 }

  condition:
    any of them
}