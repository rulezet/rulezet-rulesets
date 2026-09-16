rule TTP_XOR_WriteProcessMemory_70e9 {
  strings:
    $key_70e9 = { 27 9b [2] 15 b9 [2] 13 8c [2] 3d 8c [2] 02 90 }

  condition:
    any of them
}