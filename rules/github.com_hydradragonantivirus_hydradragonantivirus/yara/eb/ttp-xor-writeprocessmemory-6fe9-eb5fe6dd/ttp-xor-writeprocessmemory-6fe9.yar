rule TTP_XOR_WriteProcessMemory_6fe9 {
  strings:
    $key_6fe9 = { 38 9b [2] 0a b9 [2] 0c 8c [2] 22 8c [2] 1d 90 }

  condition:
    any of them
}