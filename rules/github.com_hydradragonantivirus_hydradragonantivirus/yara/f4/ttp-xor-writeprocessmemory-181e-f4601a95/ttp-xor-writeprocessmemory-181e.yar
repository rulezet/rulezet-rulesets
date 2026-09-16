rule TTP_XOR_WriteProcessMemory_181e {
  strings:
    $key_181e = { 4f 6c [2] 7d 4e [2] 7b 7b [2] 55 7b [2] 6a 67 }

  condition:
    any of them
}