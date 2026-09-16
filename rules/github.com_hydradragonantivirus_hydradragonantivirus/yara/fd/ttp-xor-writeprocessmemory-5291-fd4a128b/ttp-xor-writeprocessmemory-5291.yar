rule TTP_XOR_WriteProcessMemory_5291 {
  strings:
    $key_5291 = { 05 e3 [2] 37 c1 [2] 31 f4 [2] 1f f4 [2] 20 e8 }

  condition:
    any of them
}