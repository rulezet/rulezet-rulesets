rule TTP_XOR_WriteProcessMemory_f55e {
  strings:
    $key_f55e = { a2 2c [2] 90 0e [2] 96 3b [2] b8 3b [2] 87 27 }

  condition:
    any of them
}