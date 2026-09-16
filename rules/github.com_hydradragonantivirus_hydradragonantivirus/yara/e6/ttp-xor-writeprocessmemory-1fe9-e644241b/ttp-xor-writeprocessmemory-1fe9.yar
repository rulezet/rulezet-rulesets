rule TTP_XOR_WriteProcessMemory_1fe9 {
  strings:
    $key_1fe9 = { 48 9b [2] 7a b9 [2] 7c 8c [2] 52 8c [2] 6d 90 }

  condition:
    any of them
}