rule TTP_XOR_WriteProcessMemory_7e29 {
  strings:
    $key_7e29 = { 29 5b [2] 1b 79 [2] 1d 4c [2] 33 4c [2] 0c 50 }

  condition:
    any of them
}