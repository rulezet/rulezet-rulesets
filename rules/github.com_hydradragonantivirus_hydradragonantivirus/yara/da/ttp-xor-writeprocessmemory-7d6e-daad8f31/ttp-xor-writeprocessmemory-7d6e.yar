rule TTP_XOR_WriteProcessMemory_7d6e {
  strings:
    $key_7d6e = { 2a 1c [2] 18 3e [2] 1e 0b [2] 30 0b [2] 0f 17 }

  condition:
    any of them
}