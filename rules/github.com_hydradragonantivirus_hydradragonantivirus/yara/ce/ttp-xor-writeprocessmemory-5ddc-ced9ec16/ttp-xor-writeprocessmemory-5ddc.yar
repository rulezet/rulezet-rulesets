rule TTP_XOR_WriteProcessMemory_5ddc {
  strings:
    $key_5ddc = { 0a ae [2] 38 8c [2] 3e b9 [2] 10 b9 [2] 2f a5 }

  condition:
    any of them
}