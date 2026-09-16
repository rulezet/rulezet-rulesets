rule TTP_XOR_WriteProcessMemory_661e {
  strings:
    $key_661e = { 31 6c [2] 03 4e [2] 05 7b [2] 2b 7b [2] 14 67 }

  condition:
    any of them
}