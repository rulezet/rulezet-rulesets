rule TTP_XOR_WriteProcessMemory_196e {
  strings:
    $key_196e = { 4e 1c [2] 7c 3e [2] 7a 0b [2] 54 0b [2] 6b 17 }

  condition:
    any of them
}