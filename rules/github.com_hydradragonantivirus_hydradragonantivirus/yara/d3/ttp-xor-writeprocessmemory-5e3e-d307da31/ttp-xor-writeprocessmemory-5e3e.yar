rule TTP_XOR_WriteProcessMemory_5e3e {
  strings:
    $key_5e3e = { 09 4c [2] 3b 6e [2] 3d 5b [2] 13 5b [2] 2c 47 }

  condition:
    any of them
}