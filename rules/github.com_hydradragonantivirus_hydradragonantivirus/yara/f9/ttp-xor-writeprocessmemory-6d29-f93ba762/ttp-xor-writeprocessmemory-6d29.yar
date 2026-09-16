rule TTP_XOR_WriteProcessMemory_6d29 {
  strings:
    $key_6d29 = { 3a 5b [2] 08 79 [2] 0e 4c [2] 20 4c [2] 1f 50 }

  condition:
    any of them
}