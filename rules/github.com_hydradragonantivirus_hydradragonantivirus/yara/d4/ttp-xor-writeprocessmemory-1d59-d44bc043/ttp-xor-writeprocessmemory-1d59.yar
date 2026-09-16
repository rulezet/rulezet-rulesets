rule TTP_XOR_WriteProcessMemory_1d59 {
  strings:
    $key_1d59 = { 4a 2b [2] 78 09 [2] 7e 3c [2] 50 3c [2] 6f 20 }

  condition:
    any of them
}