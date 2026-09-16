rule TTP_XOR_WriteProcessMemory_06ad {
  strings:
    $key_06ad = { 51 df [2] 63 fd [2] 65 c8 [2] 4b c8 [2] 74 d4 }

  condition:
    any of them
}