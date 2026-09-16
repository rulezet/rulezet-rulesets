rule TTP_XOR_WriteProcessMemory_547c {
  strings:
    $key_547c = { 03 0e [2] 31 2c [2] 37 19 [2] 19 19 [2] 26 05 }

  condition:
    any of them
}