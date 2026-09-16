rule TTP_XOR_WriteProcessMemory_7c29 {
  strings:
    $key_7c29 = { 2b 5b [2] 19 79 [2] 1f 4c [2] 31 4c [2] 0e 50 }

  condition:
    any of them
}