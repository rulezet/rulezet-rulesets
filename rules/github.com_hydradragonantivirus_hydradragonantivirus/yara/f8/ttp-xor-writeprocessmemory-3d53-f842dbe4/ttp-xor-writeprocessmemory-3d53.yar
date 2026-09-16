rule TTP_XOR_WriteProcessMemory_3d53 {
  strings:
    $key_3d53 = { 6a 21 [2] 58 03 [2] 5e 36 [2] 70 36 [2] 4f 2a }

  condition:
    any of them
}