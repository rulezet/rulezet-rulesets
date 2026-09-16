rule TTP_XOR_WriteProcessMemory_8774 {
  strings:
    $key_8774 = { d0 06 [2] e2 24 [2] e4 11 [2] ca 11 [2] f5 0d }

  condition:
    any of them
}