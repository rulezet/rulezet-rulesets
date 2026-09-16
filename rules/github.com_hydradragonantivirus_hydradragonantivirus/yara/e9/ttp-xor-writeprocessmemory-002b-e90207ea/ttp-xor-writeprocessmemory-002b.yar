rule TTP_XOR_WriteProcessMemory_002b {
  strings:
    $key_002b = { 57 59 [2] 65 7b [2] 63 4e [2] 4d 4e [2] 72 52 }

  condition:
    any of them
}