rule TTP_XOR_WriteProcessMemory_2c2e {
  strings:
    $key_2c2e = { 7b 5c [2] 49 7e [2] 4f 4b [2] 61 4b [2] 5e 57 }

  condition:
    any of them
}