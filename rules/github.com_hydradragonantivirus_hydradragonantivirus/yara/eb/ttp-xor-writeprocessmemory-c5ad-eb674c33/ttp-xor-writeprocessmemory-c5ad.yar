rule TTP_XOR_WriteProcessMemory_c5ad {
  strings:
    $key_c5ad = { 92 df [2] a0 fd [2] a6 c8 [2] 88 c8 [2] b7 d4 }

  condition:
    any of them
}