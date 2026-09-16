rule TTP_XOR_WriteProcessMemory_4f3e {
  strings:
    $key_4f3e = { 18 4c [2] 2a 6e [2] 2c 5b [2] 02 5b [2] 3d 47 }

  condition:
    any of them
}