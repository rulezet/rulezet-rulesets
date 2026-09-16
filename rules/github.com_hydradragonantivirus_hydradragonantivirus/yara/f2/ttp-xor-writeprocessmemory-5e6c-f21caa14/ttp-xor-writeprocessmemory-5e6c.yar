rule TTP_XOR_WriteProcessMemory_5e6c {
  strings:
    $key_5e6c = { 09 1e [2] 3b 3c [2] 3d 09 [2] 13 09 [2] 2c 15 }

  condition:
    any of them
}