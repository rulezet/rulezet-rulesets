rule TTP_XOR_WriteProcessMemory_3d92 {
  strings:
    $key_3d92 = { 6a e0 [2] 58 c2 [2] 5e f7 [2] 70 f7 [2] 4f eb }

  condition:
    any of them
}