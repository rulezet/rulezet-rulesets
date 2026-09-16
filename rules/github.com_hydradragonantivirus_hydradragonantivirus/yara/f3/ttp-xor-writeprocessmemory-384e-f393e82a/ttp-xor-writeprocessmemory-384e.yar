rule TTP_XOR_WriteProcessMemory_384e {
  strings:
    $key_384e = { 6f 3c [2] 5d 1e [2] 5b 2b [2] 75 2b [2] 4a 37 }

  condition:
    any of them
}