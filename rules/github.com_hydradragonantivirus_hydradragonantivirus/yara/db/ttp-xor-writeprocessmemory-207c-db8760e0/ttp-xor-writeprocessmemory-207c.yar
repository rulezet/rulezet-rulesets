rule TTP_XOR_WriteProcessMemory_207c {
  strings:
    $key_207c = { 77 0e [2] 45 2c [2] 43 19 [2] 6d 19 [2] 52 05 }

  condition:
    any of them
}