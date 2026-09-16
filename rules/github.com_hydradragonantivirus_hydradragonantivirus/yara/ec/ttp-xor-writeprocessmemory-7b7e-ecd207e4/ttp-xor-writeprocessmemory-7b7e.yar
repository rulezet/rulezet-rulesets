rule TTP_XOR_WriteProcessMemory_7b7e {
  strings:
    $key_7b7e = { 2c 0c [2] 1e 2e [2] 18 1b [2] 36 1b [2] 09 07 }

  condition:
    any of them
}