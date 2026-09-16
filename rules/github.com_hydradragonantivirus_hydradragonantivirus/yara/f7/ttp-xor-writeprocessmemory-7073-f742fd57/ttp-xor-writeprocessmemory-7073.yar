rule TTP_XOR_WriteProcessMemory_7073 {
  strings:
    $key_7073 = { 27 01 [2] 15 23 [2] 13 16 [2] 3d 16 [2] 02 0a }

  condition:
    any of them
}