rule TTP_XOR_WriteProcessMemory_d61e {
  strings:
    $key_d61e = { 81 6c [2] b3 4e [2] b5 7b [2] 9b 7b [2] a4 67 }

  condition:
    any of them
}