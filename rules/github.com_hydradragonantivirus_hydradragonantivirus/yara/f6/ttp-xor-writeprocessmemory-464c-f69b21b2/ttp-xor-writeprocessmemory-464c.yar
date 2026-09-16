rule TTP_XOR_WriteProcessMemory_464c {
  strings:
    $key_464c = { 11 3e [2] 23 1c [2] 25 29 [2] 0b 29 [2] 34 35 }

  condition:
    any of them
}