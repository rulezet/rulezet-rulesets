rule TTP_XOR_WriteProcessMemory_fc75 {
  strings:
    $key_fc75 = { ab 07 [2] 99 25 [2] 9f 10 [2] b1 10 [2] 8e 0c }

  condition:
    any of them
}