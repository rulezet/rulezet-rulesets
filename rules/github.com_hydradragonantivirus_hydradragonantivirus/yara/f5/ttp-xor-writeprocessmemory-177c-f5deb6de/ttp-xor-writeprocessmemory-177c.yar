rule TTP_XOR_WriteProcessMemory_177c {
  strings:
    $key_177c = { 40 0e [2] 72 2c [2] 74 19 [2] 5a 19 [2] 65 05 }

  condition:
    any of them
}