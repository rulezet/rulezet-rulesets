rule TTP_XOR_WriteProcessMemory_1cdd {
  strings:
    $key_1cdd = { 4b af [2] 79 8d [2] 7f b8 [2] 51 b8 [2] 6e a4 }

  condition:
    any of them
}