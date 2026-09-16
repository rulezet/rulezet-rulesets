rule TTP_XOR_WriteProcessMemory_3ee9 {
  strings:
    $key_3ee9 = { 69 9b [2] 5b b9 [2] 5d 8c [2] 73 8c [2] 4c 90 }

  condition:
    any of them
}