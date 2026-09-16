rule TTP_XOR_WriteProcessMemory_f1ad {
  strings:
    $key_f1ad = { a6 df [2] 94 fd [2] 92 c8 [2] bc c8 [2] 83 d4 }

  condition:
    any of them
}