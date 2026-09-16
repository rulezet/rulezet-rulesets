rule TTP_XOR_WriteProcessMemory_8392 {
  strings:
    $key_8392 = { d4 e0 [2] e6 c2 [2] e0 f7 [2] ce f7 [2] f1 eb }

  condition:
    any of them
}