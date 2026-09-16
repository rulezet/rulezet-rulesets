rule TTP_XOR_WriteProcessMemory_8201 {
  strings:
    $key_8201 = { d5 73 [2] e7 51 [2] e1 64 [2] cf 64 [2] f0 78 }

  condition:
    any of them
}