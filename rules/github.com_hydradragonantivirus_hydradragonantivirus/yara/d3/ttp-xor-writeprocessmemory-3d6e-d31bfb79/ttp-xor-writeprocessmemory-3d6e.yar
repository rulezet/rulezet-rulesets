rule TTP_XOR_WriteProcessMemory_3d6e {
  strings:
    $key_3d6e = { 6a 1c [2] 58 3e [2] 5e 0b [2] 70 0b [2] 4f 17 }

  condition:
    any of them
}