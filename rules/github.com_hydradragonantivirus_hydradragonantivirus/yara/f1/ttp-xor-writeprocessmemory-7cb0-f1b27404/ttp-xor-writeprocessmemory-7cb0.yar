rule TTP_XOR_WriteProcessMemory_7cb0 {
  strings:
    $key_7cb0 = { 2b c2 [2] 19 e0 [2] 1f d5 [2] 31 d5 [2] 0e c9 }

  condition:
    any of them
}