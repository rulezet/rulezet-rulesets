rule TTP_XOR_WriteProcessMemory_3d56 {
  strings:
    $key_3d56 = { 6a 24 [2] 58 06 [2] 5e 33 [2] 70 33 [2] 4f 2f }

  condition:
    any of them
}