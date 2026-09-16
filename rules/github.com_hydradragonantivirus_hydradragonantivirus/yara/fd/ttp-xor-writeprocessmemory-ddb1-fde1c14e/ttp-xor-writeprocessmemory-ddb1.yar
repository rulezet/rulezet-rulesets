rule TTP_XOR_WriteProcessMemory_ddb1 {
  strings:
    $key_ddb1 = { 8a c3 [2] b8 e1 [2] be d4 [2] 90 d4 [2] af c8 }

  condition:
    any of them
}