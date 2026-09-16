rule TTP_XOR_WriteProcessMemory_ebe9 {
  strings:
    $key_ebe9 = { bc 9b [2] 8e b9 [2] 88 8c [2] a6 8c [2] 99 90 }

  condition:
    any of them
}