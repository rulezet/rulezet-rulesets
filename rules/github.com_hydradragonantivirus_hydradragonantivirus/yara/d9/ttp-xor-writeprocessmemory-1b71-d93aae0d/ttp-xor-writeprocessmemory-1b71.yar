rule TTP_XOR_WriteProcessMemory_1b71 {
  strings:
    $key_1b71 = { 4c 03 [2] 7e 21 [2] 78 14 [2] 56 14 [2] 69 08 }

  condition:
    any of them
}