rule TTP_XOR_WriteProcessMemory_8443 {
  strings:
    $key_8443 = { d3 31 [2] e1 13 [2] e7 26 [2] c9 26 [2] f6 3a }

  condition:
    any of them
}