rule TTP_XOR_WriteProcessMemory_754c {
  strings:
    $key_754c = { 22 3e [2] 10 1c [2] 16 29 [2] 38 29 [2] 07 35 }

  condition:
    any of them
}