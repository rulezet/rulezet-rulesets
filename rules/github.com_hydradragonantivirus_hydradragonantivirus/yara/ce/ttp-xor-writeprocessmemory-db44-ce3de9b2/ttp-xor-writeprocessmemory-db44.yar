rule TTP_XOR_WriteProcessMemory_db44 {
  strings:
    $key_db44 = { 8c 36 [2] be 14 [2] b8 21 [2] 96 21 [2] a9 3d }

  condition:
    any of them
}