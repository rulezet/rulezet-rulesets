rule TTP_XOR_WriteProcessMemory_10b3 {
  strings:
    $key_10b3 = { 47 c1 [2] 75 e3 [2] 73 d6 [2] 5d d6 [2] 62 ca }

  condition:
    any of them
}