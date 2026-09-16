rule TTP_XOR_WriteProcessMemory_f95e {
  strings:
    $key_f95e = { ae 2c [2] 9c 0e [2] 9a 3b [2] b4 3b [2] 8b 27 }

  condition:
    any of them
}