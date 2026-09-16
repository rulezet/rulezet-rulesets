rule TTP_XOR_WriteProcessMemory_6c6e {
  strings:
    $key_6c6e = { 3b 1c [2] 09 3e [2] 0f 0b [2] 21 0b [2] 1e 17 }

  condition:
    any of them
}