rule TTP_XOR_WriteProcessMemory_4cf9 {
  strings:
    $key_4cf9 = { 1b 8b [2] 29 a9 [2] 2f 9c [2] 01 9c [2] 3e 80 }

  condition:
    any of them
}