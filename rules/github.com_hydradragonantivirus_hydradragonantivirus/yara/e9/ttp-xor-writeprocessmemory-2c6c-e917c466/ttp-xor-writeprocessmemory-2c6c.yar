rule TTP_XOR_WriteProcessMemory_2c6c {
  strings:
    $key_2c6c = { 7b 1e [2] 49 3c [2] 4f 09 [2] 61 09 [2] 5e 15 }

  condition:
    any of them
}