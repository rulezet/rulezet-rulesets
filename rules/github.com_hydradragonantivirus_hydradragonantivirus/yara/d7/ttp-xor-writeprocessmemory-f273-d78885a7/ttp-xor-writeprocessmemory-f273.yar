rule TTP_XOR_WriteProcessMemory_f273 {
  strings:
    $key_f273 = { a5 01 [2] 97 23 [2] 91 16 [2] bf 16 [2] 80 0a }

  condition:
    any of them
}