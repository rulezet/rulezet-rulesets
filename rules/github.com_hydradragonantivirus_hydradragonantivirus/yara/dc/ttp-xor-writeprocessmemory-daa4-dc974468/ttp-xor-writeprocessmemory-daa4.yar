rule TTP_XOR_WriteProcessMemory_daa4 {
  strings:
    $key_daa4 = { 8d d6 [2] bf f4 [2] b9 c1 [2] 97 c1 [2] a8 dd }

  condition:
    any of them
}