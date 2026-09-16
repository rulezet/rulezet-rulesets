rule TTP_XOR_WriteProcessMemory_18e8 {
  strings:
    $key_18e8 = { 4f 9a [2] 7d b8 [2] 7b 8d [2] 55 8d [2] 6a 91 }

  condition:
    any of them
}