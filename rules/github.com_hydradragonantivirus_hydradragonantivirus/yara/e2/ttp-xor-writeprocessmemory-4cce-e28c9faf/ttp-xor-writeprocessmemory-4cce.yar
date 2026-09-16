rule TTP_XOR_WriteProcessMemory_4cce {
  strings:
    $key_4cce = { 1b bc [2] 29 9e [2] 2f ab [2] 01 ab [2] 3e b7 }

  condition:
    any of them
}