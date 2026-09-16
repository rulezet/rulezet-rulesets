rule TTP_XOR_WriteProcessMemory_221e {
  strings:
    $key_221e = { 75 6c [2] 47 4e [2] 41 7b [2] 6f 7b [2] 50 67 }

  condition:
    any of them
}