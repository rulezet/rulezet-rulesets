rule TTP_XOR_WriteProcessMemory_e675 {
  strings:
    $key_e675 = { b1 07 [2] 83 25 [2] 85 10 [2] ab 10 [2] 94 0c }

  condition:
    any of them
}