rule TTP_XOR_WriteProcessMemory_3f6e {
  strings:
    $key_3f6e = { 68 1c [2] 5a 3e [2] 5c 0b [2] 72 0b [2] 4d 17 }

  condition:
    any of them
}