rule TTP_XOR_WriteProcessMemory_41b3 {
  strings:
    $key_41b3 = { 16 c1 [2] 24 e3 [2] 22 d6 [2] 0c d6 [2] 33 ca }

  condition:
    any of them
}