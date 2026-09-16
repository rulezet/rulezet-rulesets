rule TTP_XOR_WriteProcessMemory_2c0e {
  strings:
    $key_2c0e = { 7b 7c [2] 49 5e [2] 4f 6b [2] 61 6b [2] 5e 77 }

  condition:
    any of them
}