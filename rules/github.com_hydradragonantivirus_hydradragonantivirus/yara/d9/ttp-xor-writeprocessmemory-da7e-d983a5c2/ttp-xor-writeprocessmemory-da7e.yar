rule TTP_XOR_WriteProcessMemory_da7e {
  strings:
    $key_da7e = { 8d 0c [2] bf 2e [2] b9 1b [2] 97 1b [2] a8 07 }

  condition:
    any of them
}