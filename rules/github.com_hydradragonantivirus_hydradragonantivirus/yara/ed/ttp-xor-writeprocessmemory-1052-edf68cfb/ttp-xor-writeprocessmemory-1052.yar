rule TTP_XOR_WriteProcessMemory_1052 {
  strings:
    $key_1052 = { 47 20 [2] 75 02 [2] 73 37 [2] 5d 37 [2] 62 2b }

  condition:
    any of them
}