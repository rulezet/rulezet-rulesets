rule TTP_XOR_WriteProcessMemory_5cce {
  strings:
    $key_5cce = { 0b bc [2] 39 9e [2] 3f ab [2] 11 ab [2] 2e b7 }

  condition:
    any of them
}