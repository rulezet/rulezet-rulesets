rule TTP_XOR_WriteProcessMemory_ebe5 {
  strings:
    $key_ebe5 = { bc 97 [2] 8e b5 [2] 88 80 [2] a6 80 [2] 99 9c }

  condition:
    any of them
}