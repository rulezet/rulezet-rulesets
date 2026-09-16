rule TTP_XOR_WriteProcessMemory_2e1e {
  strings:
    $key_2e1e = { 79 6c [2] 4b 4e [2] 4d 7b [2] 63 7b [2] 5c 67 }

  condition:
    any of them
}