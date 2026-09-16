rule TTP_XOR_WriteProcessMemory_edf2 {
  strings:
    $key_edf2 = { ba 80 [2] 88 a2 [2] 8e 97 [2] a0 97 [2] 9f 8b }

  condition:
    any of them
}