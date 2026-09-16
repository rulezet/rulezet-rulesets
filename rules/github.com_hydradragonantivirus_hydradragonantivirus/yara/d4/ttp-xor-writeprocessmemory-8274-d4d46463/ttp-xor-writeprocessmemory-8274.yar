rule TTP_XOR_WriteProcessMemory_8274 {
  strings:
    $key_8274 = { d5 06 [2] e7 24 [2] e1 11 [2] cf 11 [2] f0 0d }

  condition:
    any of them
}