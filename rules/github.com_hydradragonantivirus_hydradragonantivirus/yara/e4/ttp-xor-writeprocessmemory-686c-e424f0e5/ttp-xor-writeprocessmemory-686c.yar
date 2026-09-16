rule TTP_XOR_WriteProcessMemory_686c {
  strings:
    $key_686c = { 3f 1e [2] 0d 3c [2] 0b 09 [2] 25 09 [2] 1a 15 }

  condition:
    any of them
}