rule TTP_XOR_WriteProcessMemory_ecee {
  strings:
    $key_ecee = { bb 9c [2] 89 be [2] 8f 8b [2] a1 8b [2] 9e 97 }

  condition:
    any of them
}