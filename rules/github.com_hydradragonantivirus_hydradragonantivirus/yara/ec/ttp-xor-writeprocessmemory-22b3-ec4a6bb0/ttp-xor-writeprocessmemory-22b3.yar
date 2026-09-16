rule TTP_XOR_WriteProcessMemory_22b3 {
  strings:
    $key_22b3 = { 75 c1 [2] 47 e3 [2] 41 d6 [2] 6f d6 [2] 50 ca }

  condition:
    any of them
}