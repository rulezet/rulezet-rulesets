rule TTP_XOR_WriteProcessMemory_1c69 {
  strings:
    $key_1c69 = { 4b 1b [2] 79 39 [2] 7f 0c [2] 51 0c [2] 6e 10 }

  condition:
    any of them
}