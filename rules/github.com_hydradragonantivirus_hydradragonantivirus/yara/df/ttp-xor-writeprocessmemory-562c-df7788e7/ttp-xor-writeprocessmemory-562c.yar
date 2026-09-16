rule TTP_XOR_WriteProcessMemory_562c {
  strings:
    $key_562c = { 01 5e [2] 33 7c [2] 35 49 [2] 1b 49 [2] 24 55 }

  condition:
    any of them
}