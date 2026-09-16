rule TTP_XOR_WriteProcessMemory_2f29 {
  strings:
    $key_2f29 = { 78 5b [2] 4a 79 [2] 4c 4c [2] 62 4c [2] 5d 50 }

  condition:
    any of them
}