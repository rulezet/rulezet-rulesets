rule TTP_XOR_WriteProcessMemory_4f7b {
  strings:
    $key_4f7b = { 18 09 [2] 2a 2b [2] 2c 1e [2] 02 1e [2] 3d 02 }

  condition:
    any of them
}