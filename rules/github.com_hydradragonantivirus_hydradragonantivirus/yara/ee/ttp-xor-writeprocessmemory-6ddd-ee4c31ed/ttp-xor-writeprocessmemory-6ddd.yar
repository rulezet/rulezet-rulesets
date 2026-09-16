rule TTP_XOR_WriteProcessMemory_6ddd {
  strings:
    $key_6ddd = { 3a af [2] 08 8d [2] 0e b8 [2] 20 b8 [2] 1f a4 }

  condition:
    any of them
}