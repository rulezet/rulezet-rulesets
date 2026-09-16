rule TTP_XOR_WriteProcessMemory_7759 {
  strings:
    $key_7759 = { 20 2b [2] 12 09 [2] 14 3c [2] 3a 3c [2] 05 20 }

  condition:
    any of them
}