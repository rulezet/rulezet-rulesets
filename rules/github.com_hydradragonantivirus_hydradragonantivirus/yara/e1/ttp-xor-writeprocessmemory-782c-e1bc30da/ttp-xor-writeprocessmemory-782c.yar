rule TTP_XOR_WriteProcessMemory_782c {
  strings:
    $key_782c = { 2f 5e [2] 1d 7c [2] 1b 49 [2] 35 49 [2] 0a 55 }

  condition:
    any of them
}