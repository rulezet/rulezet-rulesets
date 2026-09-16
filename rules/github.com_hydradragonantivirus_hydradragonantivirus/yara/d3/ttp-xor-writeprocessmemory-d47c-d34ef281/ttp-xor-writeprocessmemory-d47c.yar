rule TTP_XOR_WriteProcessMemory_d47c {
  strings:
    $key_d47c = { 83 0e [2] b1 2c [2] b7 19 [2] 99 19 [2] a6 05 }

  condition:
    any of them
}