rule TTP_XOR_WriteProcessMemory_307c {
  strings:
    $key_307c = { 67 0e [2] 55 2c [2] 53 19 [2] 7d 19 [2] 42 05 }

  condition:
    any of them
}