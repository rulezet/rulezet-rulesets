rule TTP_XOR_WriteProcessMemory_32ad {
  strings:
    $key_32ad = { 65 df [2] 57 fd [2] 51 c8 [2] 7f c8 [2] 40 d4 }

  condition:
    any of them
}