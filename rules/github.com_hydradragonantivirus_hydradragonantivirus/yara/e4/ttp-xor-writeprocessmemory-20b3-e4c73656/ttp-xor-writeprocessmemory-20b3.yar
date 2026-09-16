rule TTP_XOR_WriteProcessMemory_20b3 {
  strings:
    $key_20b3 = { 77 c1 [2] 45 e3 [2] 43 d6 [2] 6d d6 [2] 52 ca }

  condition:
    any of them
}