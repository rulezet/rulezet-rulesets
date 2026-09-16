rule TTP_XOR_WriteProcessMemory_374c {
  strings:
    $key_374c = { 60 3e [2] 52 1c [2] 54 29 [2] 7a 29 [2] 45 35 }

  condition:
    any of them
}