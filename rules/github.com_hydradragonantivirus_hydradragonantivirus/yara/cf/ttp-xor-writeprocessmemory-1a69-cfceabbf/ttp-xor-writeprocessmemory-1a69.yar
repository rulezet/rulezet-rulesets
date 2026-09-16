rule TTP_XOR_WriteProcessMemory_1a69 {
  strings:
    $key_1a69 = { 4d 1b [2] 7f 39 [2] 79 0c [2] 57 0c [2] 68 10 }

  condition:
    any of them
}