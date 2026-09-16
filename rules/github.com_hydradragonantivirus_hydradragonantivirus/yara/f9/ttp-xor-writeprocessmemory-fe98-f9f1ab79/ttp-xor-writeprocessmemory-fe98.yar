rule TTP_XOR_WriteProcessMemory_fe98 {
  strings:
    $key_fe98 = { a9 ea [2] 9b c8 [2] 9d fd [2] b3 fd [2] 8c e1 }

  condition:
    any of them
}