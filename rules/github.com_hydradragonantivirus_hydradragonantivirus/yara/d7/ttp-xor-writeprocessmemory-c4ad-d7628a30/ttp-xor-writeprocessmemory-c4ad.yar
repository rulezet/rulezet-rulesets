rule TTP_XOR_WriteProcessMemory_c4ad {
  strings:
    $key_c4ad = { 93 df [2] a1 fd [2] a7 c8 [2] 89 c8 [2] b6 d4 }

  condition:
    any of them
}