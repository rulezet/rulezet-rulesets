rule TTP_XOR_WriteProcessMemory_f5e5 {
  strings:
    $key_f5e5 = { a2 97 [2] 90 b5 [2] 96 80 [2] b8 80 [2] 87 9c }

  condition:
    any of them
}