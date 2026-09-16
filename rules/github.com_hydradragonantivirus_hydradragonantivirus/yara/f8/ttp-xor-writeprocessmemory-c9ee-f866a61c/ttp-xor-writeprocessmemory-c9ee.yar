rule TTP_XOR_WriteProcessMemory_c9ee {
  strings:
    $key_c9ee = { 9e 9c [2] ac be [2] aa 8b [2] 84 8b [2] bb 97 }

  condition:
    any of them
}