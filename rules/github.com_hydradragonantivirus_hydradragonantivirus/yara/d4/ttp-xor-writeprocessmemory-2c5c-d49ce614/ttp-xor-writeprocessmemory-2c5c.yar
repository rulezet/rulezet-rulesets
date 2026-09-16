rule TTP_XOR_WriteProcessMemory_2c5c {
  strings:
    $key_2c5c = { 7b 2e [2] 49 0c [2] 4f 39 [2] 61 39 [2] 5e 25 }

  condition:
    any of them
}