rule TTP_XOR_WriteProcessMemory_42e9 {
  strings:
    $key_42e9 = { 15 9b [2] 27 b9 [2] 21 8c [2] 0f 8c [2] 30 90 }

  condition:
    any of them
}