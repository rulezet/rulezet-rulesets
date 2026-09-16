rule TTP_XOR_WriteProcessMemory_176e {
  strings:
    $key_176e = { 40 1c [2] 72 3e [2] 74 0b [2] 5a 0b [2] 65 17 }

  condition:
    any of them
}