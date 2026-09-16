rule TTP_XOR_WriteProcessMemory_6c4e {
  strings:
    $key_6c4e = { 3b 3c [2] 09 1e [2] 0f 2b [2] 21 2b [2] 1e 37 }

  condition:
    any of them
}