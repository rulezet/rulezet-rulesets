rule TTP_XOR_WriteProcessMemory_da0e {
  strings:
    $key_da0e = { 8d 7c [2] bf 5e [2] b9 6b [2] 97 6b [2] a8 77 }

  condition:
    any of them
}