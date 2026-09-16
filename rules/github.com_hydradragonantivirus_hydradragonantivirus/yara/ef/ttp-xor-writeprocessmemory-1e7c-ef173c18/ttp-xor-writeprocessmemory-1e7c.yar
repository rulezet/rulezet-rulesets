rule TTP_XOR_WriteProcessMemory_1e7c {
  strings:
    $key_1e7c = { 49 0e [2] 7b 2c [2] 7d 19 [2] 53 19 [2] 6c 05 }

  condition:
    any of them
}