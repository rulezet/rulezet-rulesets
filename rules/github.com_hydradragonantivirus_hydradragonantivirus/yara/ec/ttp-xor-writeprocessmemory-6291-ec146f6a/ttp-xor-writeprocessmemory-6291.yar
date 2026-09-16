rule TTP_XOR_WriteProcessMemory_6291 {
  strings:
    $key_6291 = { 35 e3 [2] 07 c1 [2] 01 f4 [2] 2f f4 [2] 10 e8 }

  condition:
    any of them
}