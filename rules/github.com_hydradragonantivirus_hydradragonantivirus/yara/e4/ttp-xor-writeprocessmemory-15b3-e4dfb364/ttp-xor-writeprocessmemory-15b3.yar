rule TTP_XOR_WriteProcessMemory_15b3 {
  strings:
    $key_15b3 = { 42 c1 [2] 70 e3 [2] 76 d6 [2] 58 d6 [2] 67 ca }

  condition:
    any of them
}