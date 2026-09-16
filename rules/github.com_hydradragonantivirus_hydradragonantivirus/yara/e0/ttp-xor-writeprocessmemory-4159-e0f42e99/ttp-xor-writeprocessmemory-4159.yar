rule TTP_XOR_WriteProcessMemory_4159 {
  strings:
    $key_4159 = { 16 2b [2] 24 09 [2] 22 3c [2] 0c 3c [2] 33 20 }

  condition:
    any of them
}