rule TTP_XOR_WriteProcessMemory_8417 {
  strings:
    $key_8417 = { d3 65 [2] e1 47 [2] e7 72 [2] c9 72 [2] f6 6e }

  condition:
    any of them
}