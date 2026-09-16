rule TTP_XOR_WriteProcessMemory_7841 {
  strings:
    $key_7841 = { 2f 33 [2] 1d 11 [2] 1b 24 [2] 35 24 [2] 0a 38 }

  condition:
    any of them
}