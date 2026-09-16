rule TTP_XOR_WriteProcessMemory_3d5e {
  strings:
    $key_3d5e = { 6a 2c [2] 58 0e [2] 5e 3b [2] 70 3b [2] 4f 27 }

  condition:
    any of them
}