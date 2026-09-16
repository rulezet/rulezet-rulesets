rule TTP_XOR_WriteProcessMemory_4ac8 {
  strings:
    $key_4ac8 = { 1d ba [2] 2f 98 [2] 29 ad [2] 07 ad [2] 38 b1 }

  condition:
    any of them
}