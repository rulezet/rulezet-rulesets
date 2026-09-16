rule TTP_XOR_WriteProcessMemory_8ccd {
  strings:
    $key_8ccd = { db bf [2] e9 9d [2] ef a8 [2] c1 a8 [2] fe b4 }

  condition:
    any of them
}