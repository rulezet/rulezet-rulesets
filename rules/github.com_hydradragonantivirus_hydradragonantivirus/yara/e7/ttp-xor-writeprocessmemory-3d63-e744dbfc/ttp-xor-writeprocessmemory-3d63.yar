rule TTP_XOR_WriteProcessMemory_3d63 {
  strings:
    $key_3d63 = { 6a 11 [2] 58 33 [2] 5e 06 [2] 70 06 [2] 4f 1a }

  condition:
    any of them
}