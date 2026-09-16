rule TTP_XOR_WriteProcessMemory_37b3 {
  strings:
    $key_37b3 = { 60 c1 [2] 52 e3 [2] 54 d6 [2] 7a d6 [2] 45 ca }

  condition:
    any of them
}