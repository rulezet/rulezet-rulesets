rule TTP_XOR_WriteProcessMemory_c01c {
  strings:
    $key_c01c = { 97 6e [2] a5 4c [2] a3 79 [2] 8d 79 [2] b2 65 }

  condition:
    any of them
}