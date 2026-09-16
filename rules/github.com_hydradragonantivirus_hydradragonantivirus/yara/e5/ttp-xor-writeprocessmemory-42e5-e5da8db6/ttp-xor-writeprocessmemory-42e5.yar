rule TTP_XOR_WriteProcessMemory_42e5 {
  strings:
    $key_42e5 = { 15 97 [2] 27 b5 [2] 21 80 [2] 0f 80 [2] 30 9c }

  condition:
    any of them
}