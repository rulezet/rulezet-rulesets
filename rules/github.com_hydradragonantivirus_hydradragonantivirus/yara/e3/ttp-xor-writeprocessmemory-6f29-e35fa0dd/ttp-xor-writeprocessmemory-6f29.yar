rule TTP_XOR_WriteProcessMemory_6f29 {
  strings:
    $key_6f29 = { 38 5b [2] 0a 79 [2] 0c 4c [2] 22 4c [2] 1d 50 }

  condition:
    any of them
}