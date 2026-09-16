rule TTP_XOR_WriteProcessMemory_9307 {
  strings:
    $key_9307 = { c4 75 [2] f6 57 [2] f0 62 [2] de 62 [2] e1 7e }

  condition:
    any of them
}