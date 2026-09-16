rule TTP_XOR_WriteProcessMemory_714c {
  strings:
    $key_714c = { 26 3e [2] 14 1c [2] 12 29 [2] 3c 29 [2] 03 35 }

  condition:
    any of them
}