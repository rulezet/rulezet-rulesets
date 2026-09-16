rule TTP_XOR_WriteProcessMemory_4759 {
  strings:
    $key_4759 = { 10 2b [2] 22 09 [2] 24 3c [2] 0a 3c [2] 35 20 }

  condition:
    any of them
}