rule TTP_XOR_WriteProcessMemory_a943 {
  strings:
    $key_a943 = { fe 31 [2] cc 13 [2] ca 26 [2] e4 26 [2] db 3a }

  condition:
    any of them
}