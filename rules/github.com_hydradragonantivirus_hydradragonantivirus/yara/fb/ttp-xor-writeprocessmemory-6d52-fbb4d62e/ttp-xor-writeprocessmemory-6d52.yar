rule TTP_XOR_WriteProcessMemory_6d52 {
  strings:
    $key_6d52 = { 3a 20 [2] 08 02 [2] 0e 37 [2] 20 37 [2] 1f 2b }

  condition:
    any of them
}