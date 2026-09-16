rule TTP_XOR_WriteProcessMemory_8236 {
  strings:
    $key_8236 = { d5 44 [2] e7 66 [2] e1 53 [2] cf 53 [2] f0 4f }

  condition:
    any of them
}