rule TTP_XOR_WriteProcessMemory_f619 {
  strings:
    $key_f619 = { a1 6b [2] 93 49 [2] 95 7c [2] bb 7c [2] 84 60 }

  condition:
    any of them
}