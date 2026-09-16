rule TTP_XOR_WriteProcessMemory_3d44 {
  strings:
    $key_3d44 = { 6a 36 [2] 58 14 [2] 5e 21 [2] 70 21 [2] 4f 3d }

  condition:
    any of them
}