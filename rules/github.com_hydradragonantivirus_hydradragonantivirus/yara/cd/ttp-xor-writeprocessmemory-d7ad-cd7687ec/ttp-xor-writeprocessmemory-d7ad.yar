rule TTP_XOR_WriteProcessMemory_d7ad {
  strings:
    $key_d7ad = { 80 df [2] b2 fd [2] b4 c8 [2] 9a c8 [2] a5 d4 }

  condition:
    any of them
}