rule TTP_XOR_WriteProcessMemory_f3ed {
  strings:
    $key_f3ed = { a4 9f [2] 96 bd [2] 90 88 [2] be 88 [2] 81 94 }

  condition:
    any of them
}