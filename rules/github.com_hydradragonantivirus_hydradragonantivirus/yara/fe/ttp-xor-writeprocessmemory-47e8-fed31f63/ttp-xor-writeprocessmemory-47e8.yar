rule TTP_XOR_WriteProcessMemory_47e8 {
  strings:
    $key_47e8 = { 10 9a [2] 22 b8 [2] 24 8d [2] 0a 8d [2] 35 91 }

  condition:
    any of them
}