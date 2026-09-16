rule TTP_XOR_WriteProcessMemory_e575 {
  strings:
    $key_e575 = { b2 07 [2] 80 25 [2] 86 10 [2] a8 10 [2] 97 0c }

  condition:
    any of them
}