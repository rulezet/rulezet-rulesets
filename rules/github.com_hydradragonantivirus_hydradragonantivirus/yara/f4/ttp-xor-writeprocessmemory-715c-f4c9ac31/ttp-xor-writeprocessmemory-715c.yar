rule TTP_XOR_WriteProcessMemory_715c {
  strings:
    $key_715c = { 26 2e [2] 14 0c [2] 12 39 [2] 3c 39 [2] 03 25 }

  condition:
    any of them
}