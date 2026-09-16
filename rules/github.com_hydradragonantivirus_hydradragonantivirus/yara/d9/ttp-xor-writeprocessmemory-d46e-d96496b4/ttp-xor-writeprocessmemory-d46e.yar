rule TTP_XOR_WriteProcessMemory_d46e {
  strings:
    $key_d46e = { 83 1c [2] b1 3e [2] b7 0b [2] 99 0b [2] a6 17 }

  condition:
    any of them
}