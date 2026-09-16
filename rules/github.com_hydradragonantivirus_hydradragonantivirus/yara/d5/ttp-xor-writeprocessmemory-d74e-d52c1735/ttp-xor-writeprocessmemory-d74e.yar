rule TTP_XOR_WriteProcessMemory_d74e {
  strings:
    $key_d74e = { 80 3c [2] b2 1e [2] b4 2b [2] 9a 2b [2] a5 37 }

  condition:
    any of them
}