rule TTP_XOR_WriteProcessMemory_760e {
  strings:
    $key_760e = { 21 7c [2] 13 5e [2] 15 6b [2] 3b 6b [2] 04 77 }

  condition:
    any of them
}