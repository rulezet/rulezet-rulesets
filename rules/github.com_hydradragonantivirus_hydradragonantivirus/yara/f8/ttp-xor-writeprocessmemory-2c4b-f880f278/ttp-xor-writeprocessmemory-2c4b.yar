rule TTP_XOR_WriteProcessMemory_2c4b {
  strings:
    $key_2c4b = { 7b 39 [2] 49 1b [2] 4f 2e [2] 61 2e [2] 5e 32 }

  condition:
    any of them
}