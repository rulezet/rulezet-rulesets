rule TTP_XOR_WriteProcessMemory_7252 {
  strings:
    $key_7252 = { 25 20 [2] 17 02 [2] 11 37 [2] 3f 37 [2] 00 2b }

  condition:
    any of them
}