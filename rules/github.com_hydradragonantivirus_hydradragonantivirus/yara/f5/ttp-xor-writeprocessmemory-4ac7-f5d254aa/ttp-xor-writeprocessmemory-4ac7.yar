rule TTP_XOR_WriteProcessMemory_4ac7 {
  strings:
    $key_4ac7 = { 1d b5 [2] 2f 97 [2] 29 a2 [2] 07 a2 [2] 38 be }

  condition:
    any of them
}