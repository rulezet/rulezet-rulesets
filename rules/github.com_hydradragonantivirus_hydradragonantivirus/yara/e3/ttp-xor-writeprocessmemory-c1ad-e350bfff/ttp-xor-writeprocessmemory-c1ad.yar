rule TTP_XOR_WriteProcessMemory_c1ad {
  strings:
    $key_c1ad = { 96 df [2] a4 fd [2] a2 c8 [2] 8c c8 [2] b3 d4 }

  condition:
    any of them
}