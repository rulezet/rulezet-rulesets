rule TTP_XOR_WriteProcessMemory_393e {
  strings:
    $key_393e = { 6e 4c [2] 5c 6e [2] 5a 5b [2] 74 5b [2] 4b 47 }

  condition:
    any of them
}