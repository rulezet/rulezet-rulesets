rule TTP_XOR_WriteProcessMemory_3c5c {
  strings:
    $key_3c5c = { 6b 2e [2] 59 0c [2] 5f 39 [2] 71 39 [2] 4e 25 }

  condition:
    any of them
}