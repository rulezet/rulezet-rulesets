rule TTP_XOR_WriteProcessMemory_e63e {
  strings:
    $key_e63e = { b1 4c [2] 83 6e [2] 85 5b [2] ab 5b [2] 94 47 }

  condition:
    any of them
}