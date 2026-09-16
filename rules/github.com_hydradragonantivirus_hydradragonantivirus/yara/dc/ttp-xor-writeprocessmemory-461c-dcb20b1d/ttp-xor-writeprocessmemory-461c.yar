rule TTP_XOR_WriteProcessMemory_461c {
  strings:
    $key_461c = { 11 6e [2] 23 4c [2] 25 79 [2] 0b 79 [2] 34 65 }

  condition:
    any of them
}