rule TTP_XOR_WriteProcessMemory_56b3 {
  strings:
    $key_56b3 = { 01 c1 [2] 33 e3 [2] 35 d6 [2] 1b d6 [2] 24 ca }

  condition:
    any of them
}