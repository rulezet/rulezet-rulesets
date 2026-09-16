rule TTP_XOR_WriteProcessMemory_6252 {
  strings:
    $key_6252 = { 35 20 [2] 07 02 [2] 01 37 [2] 2f 37 [2] 10 2b }

  condition:
    any of them
}