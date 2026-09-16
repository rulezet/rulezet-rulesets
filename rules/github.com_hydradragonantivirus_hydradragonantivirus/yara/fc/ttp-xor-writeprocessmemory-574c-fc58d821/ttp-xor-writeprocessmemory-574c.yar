rule TTP_XOR_WriteProcessMemory_574c {
  strings:
    $key_574c = { 00 3e [2] 32 1c [2] 34 29 [2] 1a 29 [2] 25 35 }

  condition:
    any of them
}