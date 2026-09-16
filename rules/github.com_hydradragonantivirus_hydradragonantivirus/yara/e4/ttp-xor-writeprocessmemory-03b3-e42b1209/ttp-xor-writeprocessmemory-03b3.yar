rule TTP_XOR_WriteProcessMemory_03b3 {
  strings:
    $key_03b3 = { 54 c1 [2] 66 e3 [2] 60 d6 [2] 4e d6 [2] 71 ca }

  condition:
    any of them
}