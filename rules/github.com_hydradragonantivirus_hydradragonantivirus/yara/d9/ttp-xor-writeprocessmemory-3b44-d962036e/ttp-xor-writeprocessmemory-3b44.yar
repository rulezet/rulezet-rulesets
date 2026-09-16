rule TTP_XOR_WriteProcessMemory_3b44 {
  strings:
    $key_3b44 = { 6c 36 [2] 5e 14 [2] 58 21 [2] 76 21 [2] 49 3d }

  condition:
    any of them
}