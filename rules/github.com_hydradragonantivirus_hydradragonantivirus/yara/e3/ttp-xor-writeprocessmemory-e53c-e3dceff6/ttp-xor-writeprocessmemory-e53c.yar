rule TTP_XOR_WriteProcessMemory_e53c {
  strings:
    $key_e53c = { b2 4e [2] 80 6c [2] 86 59 [2] a8 59 [2] 97 45 }

  condition:
    any of them
}