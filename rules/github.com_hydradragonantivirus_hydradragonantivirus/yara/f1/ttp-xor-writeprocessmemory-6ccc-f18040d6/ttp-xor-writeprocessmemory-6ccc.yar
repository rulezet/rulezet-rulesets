rule TTP_XOR_WriteProcessMemory_6ccc {
  strings:
    $key_6ccc = { 3b be [2] 09 9c [2] 0f a9 [2] 21 a9 [2] 1e b5 }

  condition:
    any of them
}