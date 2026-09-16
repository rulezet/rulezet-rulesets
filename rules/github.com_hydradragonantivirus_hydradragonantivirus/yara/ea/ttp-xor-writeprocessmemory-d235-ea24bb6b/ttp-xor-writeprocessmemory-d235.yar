rule TTP_XOR_WriteProcessMemory_d235 {
  strings:
    $key_d235 = { 85 47 [2] b7 65 [2] b1 50 [2] 9f 50 [2] a0 4c }

  condition:
    any of them
}