rule TTP_XOR_WriteProcessMemory_13b3 {
  strings:
    $key_13b3 = { 44 c1 [2] 76 e3 [2] 70 d6 [2] 5e d6 [2] 61 ca }

  condition:
    any of them
}