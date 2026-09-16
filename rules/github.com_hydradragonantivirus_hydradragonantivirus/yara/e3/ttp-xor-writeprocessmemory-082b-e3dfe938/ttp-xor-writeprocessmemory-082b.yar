rule TTP_XOR_WriteProcessMemory_082b {
  strings:
    $key_082b = { 5f 59 [2] 6d 7b [2] 6b 4e [2] 45 4e [2] 7a 52 }

  condition:
    any of them
}