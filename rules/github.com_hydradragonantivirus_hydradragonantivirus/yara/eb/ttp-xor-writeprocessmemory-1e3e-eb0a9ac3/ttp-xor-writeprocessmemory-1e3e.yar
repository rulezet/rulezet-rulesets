rule TTP_XOR_WriteProcessMemory_1e3e {
  strings:
    $key_1e3e = { 49 4c [2] 7b 6e [2] 7d 5b [2] 53 5b [2] 6c 47 }

  condition:
    any of them
}