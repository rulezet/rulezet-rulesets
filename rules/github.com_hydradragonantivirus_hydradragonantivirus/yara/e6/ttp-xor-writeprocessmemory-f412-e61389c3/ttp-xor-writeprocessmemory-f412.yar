rule TTP_XOR_WriteProcessMemory_f412 {
  strings:
    $key_f412 = { a3 60 [2] 91 42 [2] 97 77 [2] b9 77 [2] 86 6b }

  condition:
    any of them
}