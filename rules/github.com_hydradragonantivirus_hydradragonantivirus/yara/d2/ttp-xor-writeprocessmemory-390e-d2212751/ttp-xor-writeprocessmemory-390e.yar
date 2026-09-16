rule TTP_XOR_WriteProcessMemory_390e {
  strings:
    $key_390e = { 6e 7c [2] 5c 5e [2] 5a 6b [2] 74 6b [2] 4b 77 }

  condition:
    any of them
}