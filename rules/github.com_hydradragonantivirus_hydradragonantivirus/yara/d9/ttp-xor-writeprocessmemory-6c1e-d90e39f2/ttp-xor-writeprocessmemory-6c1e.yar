rule TTP_XOR_WriteProcessMemory_6c1e {
  strings:
    $key_6c1e = { 3b 6c [2] 09 4e [2] 0f 7b [2] 21 7b [2] 1e 67 }

  condition:
    any of them
}