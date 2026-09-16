rule TTP_XOR_WriteProcessMemory_4169 {
  strings:
    $key_4169 = { 16 1b [2] 24 39 [2] 22 0c [2] 0c 0c [2] 33 10 }

  condition:
    any of them
}