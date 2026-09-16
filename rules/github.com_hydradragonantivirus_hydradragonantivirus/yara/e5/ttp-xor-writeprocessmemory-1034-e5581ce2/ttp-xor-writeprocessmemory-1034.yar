rule TTP_XOR_WriteProcessMemory_1034 {
  strings:
    $key_1034 = { 47 46 [2] 75 64 [2] 73 51 [2] 5d 51 [2] 62 4d }

  condition:
    any of them
}