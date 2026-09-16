rule TTP_XOR_WriteProcessMemory_393b {
  strings:
    $key_393b = { 6e 49 [2] 5c 6b [2] 5a 5e [2] 74 5e [2] 4b 42 }

  condition:
    any of them
}