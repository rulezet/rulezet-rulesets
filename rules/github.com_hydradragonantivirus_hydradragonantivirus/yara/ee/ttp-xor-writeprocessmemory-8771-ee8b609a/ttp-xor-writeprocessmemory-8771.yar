rule TTP_XOR_WriteProcessMemory_8771 {
  strings:
    $key_8771 = { d0 03 [2] e2 21 [2] e4 14 [2] ca 14 [2] f5 08 }

  condition:
    any of them
}