rule TTP_XOR_WriteProcessMemory_6369 {
  strings:
    $key_6369 = { 34 1b [2] 06 39 [2] 00 0c [2] 2e 0c [2] 11 10 }

  condition:
    any of them
}