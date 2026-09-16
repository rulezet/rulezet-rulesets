rule TTP_XOR_WriteProcessMemory_5059 {
  strings:
    $key_5059 = { 07 2b [2] 35 09 [2] 33 3c [2] 1d 3c [2] 22 20 }

  condition:
    any of them
}