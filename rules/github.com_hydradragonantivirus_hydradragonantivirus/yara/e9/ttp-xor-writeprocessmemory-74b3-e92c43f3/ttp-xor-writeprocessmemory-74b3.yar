rule TTP_XOR_WriteProcessMemory_74b3 {
  strings:
    $key_74b3 = { 23 c1 [2] 11 e3 [2] 17 d6 [2] 39 d6 [2] 06 ca }

  condition:
    any of them
}