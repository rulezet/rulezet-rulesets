rule TTP_XOR_WriteProcessMemory_264c {
  strings:
    $key_264c = { 71 3e [2] 43 1c [2] 45 29 [2] 6b 29 [2] 54 35 }

  condition:
    any of them
}