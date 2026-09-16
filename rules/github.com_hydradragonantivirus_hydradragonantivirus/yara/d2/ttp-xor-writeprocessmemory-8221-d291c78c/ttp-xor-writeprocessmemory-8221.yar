rule TTP_XOR_WriteProcessMemory_8221 {
  strings:
    $key_8221 = { d5 53 [2] e7 71 [2] e1 44 [2] cf 44 [2] f0 58 }

  condition:
    any of them
}