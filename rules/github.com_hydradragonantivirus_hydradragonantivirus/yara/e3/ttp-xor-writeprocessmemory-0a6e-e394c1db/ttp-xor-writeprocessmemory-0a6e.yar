rule TTP_XOR_WriteProcessMemory_0a6e {
  strings:
    $key_0a6e = { 5d 1c [2] 6f 3e [2] 69 0b [2] 47 0b [2] 78 17 }

  condition:
    any of them
}