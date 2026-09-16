rule TTP_XOR_WriteProcessMemory_2a5c {
  strings:
    $key_2a5c = { 7d 2e [2] 4f 0c [2] 49 39 [2] 67 39 [2] 58 25 }

  condition:
    any of them
}