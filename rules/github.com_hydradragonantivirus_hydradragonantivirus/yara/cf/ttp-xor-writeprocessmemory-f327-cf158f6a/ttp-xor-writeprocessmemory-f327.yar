rule TTP_XOR_WriteProcessMemory_f327 {
  strings:
    $key_f327 = { a4 55 [2] 96 77 [2] 90 42 [2] be 42 [2] 81 5e }

  condition:
    any of them
}