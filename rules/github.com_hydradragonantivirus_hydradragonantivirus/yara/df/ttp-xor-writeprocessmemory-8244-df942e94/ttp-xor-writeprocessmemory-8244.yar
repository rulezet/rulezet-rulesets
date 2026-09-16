rule TTP_XOR_WriteProcessMemory_8244 {
  strings:
    $key_8244 = { d5 36 [2] e7 14 [2] e1 21 [2] cf 21 [2] f0 3d }

  condition:
    any of them
}