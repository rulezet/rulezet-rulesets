rule TTP_XOR_WriteProcessMemory_f535 {
  strings:
    $key_f535 = { a2 47 [2] 90 65 [2] 96 50 [2] b8 50 [2] 87 4c }

  condition:
    any of them
}