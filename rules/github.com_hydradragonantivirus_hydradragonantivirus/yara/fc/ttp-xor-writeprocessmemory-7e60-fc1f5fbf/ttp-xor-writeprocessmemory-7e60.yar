rule TTP_XOR_WriteProcessMemory_7e60 {
  strings:
    $key_7e60 = { 29 12 [2] 1b 30 [2] 1d 05 [2] 33 05 [2] 0c 19 }

  condition:
    any of them
}