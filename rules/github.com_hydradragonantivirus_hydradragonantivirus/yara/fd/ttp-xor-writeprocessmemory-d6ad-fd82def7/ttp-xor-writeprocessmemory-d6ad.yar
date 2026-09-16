rule TTP_XOR_WriteProcessMemory_d6ad {
  strings:
    $key_d6ad = { 81 df [2] b3 fd [2] b5 c8 [2] 9b c8 [2] a4 d4 }

  condition:
    any of them
}