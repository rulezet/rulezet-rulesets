rule TTP_XOR_WriteProcessMemory_5a5c {
  strings:
    $key_5a5c = { 0d 2e [2] 3f 0c [2] 39 39 [2] 17 39 [2] 28 25 }

  condition:
    any of them
}