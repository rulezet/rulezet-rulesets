rule TTP_XOR_WriteProcessMemory_5f69 {
  strings:
    $key_5f69 = { 08 1b [2] 3a 39 [2] 3c 0c [2] 12 0c [2] 2d 10 }

  condition:
    any of them
}