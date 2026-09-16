rule TTP_XOR_WriteProcessMemory_e8b2 {
  strings:
    $key_e8b2 = { bf c0 [2] 8d e2 [2] 8b d7 [2] a5 d7 [2] 9a cb }

  condition:
    any of them
}