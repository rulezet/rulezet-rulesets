rule TTP_XOR_WriteProcessMemory_362b {
  strings:
    $key_362b = { 61 59 [2] 53 7b [2] 55 4e [2] 7b 4e [2] 44 52 }

  condition:
    any of them
}