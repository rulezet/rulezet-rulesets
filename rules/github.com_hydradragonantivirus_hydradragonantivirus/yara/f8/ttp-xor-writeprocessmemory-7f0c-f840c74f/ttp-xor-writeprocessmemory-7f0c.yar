rule TTP_XOR_WriteProcessMemory_7f0c {
  strings:
    $key_7f0c = { 28 7e [2] 1a 5c [2] 1c 69 [2] 32 69 [2] 0d 75 }

  condition:
    any of them
}