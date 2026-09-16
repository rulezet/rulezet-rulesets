rule TTP_XOR_WriteProcessMemory_3252 {
  strings:
    $key_3252 = { 65 20 [2] 57 02 [2] 51 37 [2] 7f 37 [2] 40 2b }

  condition:
    any of them
}