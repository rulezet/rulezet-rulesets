rule TTP_XOR_WriteProcessMemory_0bdc {
  strings:
    $key_0bdc = { 5c ae [2] 6e 8c [2] 68 b9 [2] 46 b9 [2] 79 a5 }

  condition:
    any of them
}