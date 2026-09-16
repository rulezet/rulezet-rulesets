rule TTP_XOR_WriteProcessMemory_095e {
  strings:
    $key_095e = { 5e 2c [2] 6c 0e [2] 6a 3b [2] 44 3b [2] 7b 27 }

  condition:
    any of them
}