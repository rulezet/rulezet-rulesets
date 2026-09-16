rule TTP_XOR_WriteProcessMemory_e61e {
  strings:
    $key_e61e = { b1 6c [2] 83 4e [2] 85 7b [2] ab 7b [2] 94 67 }

  condition:
    any of them
}