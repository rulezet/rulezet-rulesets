rule TTP_XOR_WriteProcessMemory_70d7 {
  strings:
    $key_70d7 = { 27 a5 [2] 15 87 [2] 13 b2 [2] 3d b2 [2] 02 ae }

  condition:
    any of them
}