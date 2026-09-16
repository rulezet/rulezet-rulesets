rule TTP_XOR_WriteProcessMemory_45b3 {
  strings:
    $key_45b3 = { 12 c1 [2] 20 e3 [2] 26 d6 [2] 08 d6 [2] 37 ca }

  condition:
    any of them
}