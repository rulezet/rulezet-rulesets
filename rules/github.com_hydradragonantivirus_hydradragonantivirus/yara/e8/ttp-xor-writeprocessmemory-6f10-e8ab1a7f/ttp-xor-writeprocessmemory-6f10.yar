rule TTP_XOR_WriteProcessMemory_6f10 {
  strings:
    $key_6f10 = { 38 62 [2] 0a 40 [2] 0c 75 [2] 22 75 [2] 1d 69 }

  condition:
    any of them
}