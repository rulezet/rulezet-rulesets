rule TTP_XOR_WriteProcessMemory_182e {
  strings:
    $key_182e = { 4f 5c [2] 7d 7e [2] 7b 4b [2] 55 4b [2] 6a 57 }

  condition:
    any of them
}