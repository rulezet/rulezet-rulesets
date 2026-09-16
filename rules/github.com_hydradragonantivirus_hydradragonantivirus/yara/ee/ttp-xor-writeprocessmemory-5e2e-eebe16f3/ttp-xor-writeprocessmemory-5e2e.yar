rule TTP_XOR_WriteProcessMemory_5e2e {
  strings:
    $key_5e2e = { 09 5c [2] 3b 7e [2] 3d 4b [2] 13 4b [2] 2c 57 }

  condition:
    any of them
}