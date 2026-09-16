rule TTP_XOR_WriteProcessMemory_d32e {
  strings:
    $key_d32e = { 84 5c [2] b6 7e [2] b0 4b [2] 9e 4b [2] a1 57 }

  condition:
    any of them
}