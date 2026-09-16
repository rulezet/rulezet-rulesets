rule TTP_XOR_WriteProcessMemory_3b1e {
  strings:
    $key_3b1e = { 6c 6c [2] 5e 4e [2] 58 7b [2] 76 7b [2] 49 67 }

  condition:
    any of them
}