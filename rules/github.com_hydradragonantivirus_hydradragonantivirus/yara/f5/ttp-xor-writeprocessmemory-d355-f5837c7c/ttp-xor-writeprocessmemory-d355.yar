rule TTP_XOR_WriteProcessMemory_d355 {
  strings:
    $key_d355 = { 84 27 [2] b6 05 [2] b0 30 [2] 9e 30 [2] a1 2c }

  condition:
    any of them
}