rule TTP_XOR_WriteProcessMemory_5b71 {
  strings:
    $key_5b71 = { 0c 03 [2] 3e 21 [2] 38 14 [2] 16 14 [2] 29 08 }

  condition:
    any of them
}