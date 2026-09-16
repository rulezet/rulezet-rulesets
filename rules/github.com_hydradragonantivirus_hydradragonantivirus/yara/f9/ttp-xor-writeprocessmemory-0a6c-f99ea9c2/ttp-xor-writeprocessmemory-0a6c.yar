rule TTP_XOR_WriteProcessMemory_0a6c {
  strings:
    $key_0a6c = { 5d 1e [2] 6f 3c [2] 69 09 [2] 47 09 [2] 78 15 }

  condition:
    any of them
}