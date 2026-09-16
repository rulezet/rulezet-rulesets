rule TTP_XOR_WriteProcessMemory_69f8 {
  strings:
    $key_69f8 = { 3e 8a [2] 0c a8 [2] 0a 9d [2] 24 9d [2] 1b 81 }

  condition:
    any of them
}