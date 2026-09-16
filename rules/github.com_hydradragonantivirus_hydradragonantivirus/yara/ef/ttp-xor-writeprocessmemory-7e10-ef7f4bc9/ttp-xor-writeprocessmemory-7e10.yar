rule TTP_XOR_WriteProcessMemory_7e10 {
  strings:
    $key_7e10 = { 29 62 [2] 1b 40 [2] 1d 75 [2] 33 75 [2] 0c 69 }

  condition:
    any of them
}