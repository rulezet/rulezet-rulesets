rule TTP_XOR_WriteProcessMemory_3d43 {
  strings:
    $key_3d43 = { 6a 31 [2] 58 13 [2] 5e 26 [2] 70 26 [2] 4f 3a }

  condition:
    any of them
}