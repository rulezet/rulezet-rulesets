rule TTP_XOR_WriteProcessMemory_1d69 {
  strings:
    $key_1d69 = { 4a 1b [2] 78 39 [2] 7e 0c [2] 50 0c [2] 6f 10 }

  condition:
    any of them
}