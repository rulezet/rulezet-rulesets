rule TTP_XOR_WriteProcessMemory_5252 {
  strings:
    $key_5252 = { 05 20 [2] 37 02 [2] 31 37 [2] 1f 37 [2] 20 2b }

  condition:
    any of them
}