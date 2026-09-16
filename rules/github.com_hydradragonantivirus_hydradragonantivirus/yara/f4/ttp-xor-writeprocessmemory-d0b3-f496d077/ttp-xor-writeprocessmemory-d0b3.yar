rule TTP_XOR_WriteProcessMemory_d0b3 {
  strings:
    $key_d0b3 = { 87 c1 [2] b5 e3 [2] b3 d6 [2] 9d d6 [2] a2 ca }

  condition:
    any of them
}