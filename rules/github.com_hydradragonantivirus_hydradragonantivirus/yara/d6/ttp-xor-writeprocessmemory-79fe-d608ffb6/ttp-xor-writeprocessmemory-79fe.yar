rule TTP_XOR_WriteProcessMemory_79fe {
  strings:
    $key_79fe = { 2e 8c [2] 1c ae [2] 1a 9b [2] 34 9b [2] 0b 87 }

  condition:
    any of them
}