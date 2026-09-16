rule TTP_XOR_WriteProcessMemory_731e {
  strings:
    $key_731e = { 24 6c [2] 16 4e [2] 10 7b [2] 3e 7b [2] 01 67 }

  condition:
    any of them
}