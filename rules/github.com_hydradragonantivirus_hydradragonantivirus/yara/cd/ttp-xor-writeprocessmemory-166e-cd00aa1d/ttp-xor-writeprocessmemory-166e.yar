rule TTP_XOR_WriteProcessMemory_166e {
  strings:
    $key_166e = { 41 1c [2] 73 3e [2] 75 0b [2] 5b 0b [2] 64 17 }

  condition:
    any of them
}