rule TTP_XOR_WriteProcessMemory_4cdd {
  strings:
    $key_4cdd = { 1b af [2] 29 8d [2] 2f b8 [2] 01 b8 [2] 3e a4 }

  condition:
    any of them
}