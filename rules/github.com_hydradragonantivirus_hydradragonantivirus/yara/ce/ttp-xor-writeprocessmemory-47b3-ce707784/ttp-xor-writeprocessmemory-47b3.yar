rule TTP_XOR_WriteProcessMemory_47b3 {
  strings:
    $key_47b3 = { 10 c1 [2] 22 e3 [2] 24 d6 [2] 0a d6 [2] 35 ca }

  condition:
    any of them
}