rule TTP_XOR_WriteProcessMemory_f313 {
  strings:
    $key_f313 = { a4 61 [2] 96 43 [2] 90 76 [2] be 76 [2] 81 6a }

  condition:
    any of them
}