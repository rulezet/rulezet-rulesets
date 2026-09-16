rule TTP_XOR_WriteProcessMemory_f3ee {
  strings:
    $key_f3ee = { a4 9c [2] 96 be [2] 90 8b [2] be 8b [2] 81 97 }

  condition:
    any of them
}