rule TTP_XOR_WriteProcessMemory_e515 {
  strings:
    $key_e515 = { b2 67 [2] 80 45 [2] 86 70 [2] a8 70 [2] 97 6c }

  condition:
    any of them
}