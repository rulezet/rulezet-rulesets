rule TTP_XOR_WriteProcessMemory_071e {
  strings:
    $key_071e = { 50 6c [2] 62 4e [2] 64 7b [2] 4a 7b [2] 75 67 }

  condition:
    any of them
}