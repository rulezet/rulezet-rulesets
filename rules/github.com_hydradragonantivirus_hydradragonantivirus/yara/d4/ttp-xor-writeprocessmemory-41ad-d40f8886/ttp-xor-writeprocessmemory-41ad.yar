rule TTP_XOR_WriteProcessMemory_41ad {
  strings:
    $key_41ad = { 16 df [2] 24 fd [2] 22 c8 [2] 0c c8 [2] 33 d4 }

  condition:
    any of them
}