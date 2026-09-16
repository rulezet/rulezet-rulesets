rule TTP_XOR_WriteProcessMemory_e545 {
  strings:
    $key_e545 = { b2 37 [2] 80 15 [2] 86 20 [2] a8 20 [2] 97 3c }

  condition:
    any of them
}