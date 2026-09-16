rule TTP_XOR_WriteProcessMemory_1ddd {
  strings:
    $key_1ddd = { 4a af [2] 78 8d [2] 7e b8 [2] 50 b8 [2] 6f a4 }

  condition:
    any of them
}