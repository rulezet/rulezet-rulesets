rule TTP_XOR_WriteProcessMemory_421e {
  strings:
    $key_421e = { 15 6c [2] 27 4e [2] 21 7b [2] 0f 7b [2] 30 67 }

  condition:
    any of them
}