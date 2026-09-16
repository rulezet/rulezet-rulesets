rule TTP_XOR_WriteProcessMemory_d05b {
  strings:
    $key_d05b = { 87 29 [2] b5 0b [2] b3 3e [2] 9d 3e [2] a2 22 }

  condition:
    any of them
}