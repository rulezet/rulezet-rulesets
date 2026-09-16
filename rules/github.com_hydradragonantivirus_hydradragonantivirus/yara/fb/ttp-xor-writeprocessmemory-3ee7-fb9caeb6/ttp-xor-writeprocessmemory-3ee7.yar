rule TTP_XOR_WriteProcessMemory_3ee7 {
  strings:
    $key_3ee7 = { 69 95 [2] 5b b7 [2] 5d 82 [2] 73 82 [2] 4c 9e }

  condition:
    any of them
}