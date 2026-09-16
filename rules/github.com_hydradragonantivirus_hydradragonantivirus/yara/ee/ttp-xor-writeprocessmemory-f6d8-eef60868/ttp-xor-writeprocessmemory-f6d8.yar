rule TTP_XOR_WriteProcessMemory_f6d8 {
  strings:
    $key_f6d8 = { a1 aa [2] 93 88 [2] 95 bd [2] bb bd [2] 84 a1 }

  condition:
    any of them
}