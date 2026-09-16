rule TTP_XOR_WriteProcessMemory_db98 {
  strings:
    $key_db98 = { 8c ea [2] be c8 [2] b8 fd [2] 96 fd [2] a9 e1 }

  condition:
    any of them
}