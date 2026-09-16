rule TTP_XOR_WriteProcessMemory_1c0e {
  strings:
    $key_1c0e = { 4b 7c [2] 79 5e [2] 7f 6b [2] 51 6b [2] 6e 77 }

  condition:
    any of them
}