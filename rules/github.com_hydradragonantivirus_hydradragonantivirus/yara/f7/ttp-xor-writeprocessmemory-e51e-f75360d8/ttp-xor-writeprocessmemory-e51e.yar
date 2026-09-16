rule TTP_XOR_WriteProcessMemory_e51e {
  strings:
    $key_e51e = { b2 6c [2] 80 4e [2] 86 7b [2] a8 7b [2] 97 67 }

  condition:
    any of them
}