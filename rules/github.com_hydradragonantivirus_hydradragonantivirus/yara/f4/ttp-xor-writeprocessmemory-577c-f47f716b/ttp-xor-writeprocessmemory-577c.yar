rule TTP_XOR_WriteProcessMemory_577c {
  strings:
    $key_577c = { 00 0e [2] 32 2c [2] 34 19 [2] 1a 19 [2] 25 05 }

  condition:
    any of them
}