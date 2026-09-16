rule TTP_XOR_WriteProcessMemory_171c {
  strings:
    $key_171c = { 40 6e [2] 72 4c [2] 74 79 [2] 5a 79 [2] 65 65 }

  condition:
    any of them
}