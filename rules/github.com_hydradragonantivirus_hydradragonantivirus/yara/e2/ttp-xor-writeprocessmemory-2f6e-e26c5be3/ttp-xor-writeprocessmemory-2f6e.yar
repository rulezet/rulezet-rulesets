rule TTP_XOR_WriteProcessMemory_2f6e {
  strings:
    $key_2f6e = { 78 1c [2] 4a 3e [2] 4c 0b [2] 62 0b [2] 5d 17 }

  condition:
    any of them
}