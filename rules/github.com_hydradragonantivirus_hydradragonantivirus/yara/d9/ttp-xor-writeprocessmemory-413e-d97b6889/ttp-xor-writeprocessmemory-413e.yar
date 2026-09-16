rule TTP_XOR_WriteProcessMemory_413e {
  strings:
    $key_413e = { 16 4c [2] 24 6e [2] 22 5b [2] 0c 5b [2] 33 47 }

  condition:
    any of them
}