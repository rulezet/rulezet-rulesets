rule TTP_XOR_WriteProcessMemory_0d60 {
  strings:
    $key_0d60 = { 5a 12 [2] 68 30 [2] 6e 05 [2] 40 05 [2] 7f 19 }

  condition:
    any of them
}