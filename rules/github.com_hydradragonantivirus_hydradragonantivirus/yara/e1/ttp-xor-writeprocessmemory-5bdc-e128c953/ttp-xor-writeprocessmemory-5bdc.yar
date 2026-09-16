rule TTP_XOR_WriteProcessMemory_5bdc {
  strings:
    $key_5bdc = { 0c ae [2] 3e 8c [2] 38 b9 [2] 16 b9 [2] 29 a5 }

  condition:
    any of them
}