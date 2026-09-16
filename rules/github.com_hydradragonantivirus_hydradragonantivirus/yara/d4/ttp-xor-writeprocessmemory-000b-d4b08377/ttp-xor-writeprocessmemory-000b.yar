rule TTP_XOR_WriteProcessMemory_000b {
  strings:
    $key_000b = { 57 79 [2] 65 5b [2] 63 6e [2] 4d 6e [2] 72 72 }

  condition:
    any of them
}