rule TTP_XOR_WriteProcessMemory_e8c5 {
  strings:
    $key_e8c5 = { bf b7 [2] 8d 95 [2] 8b a0 [2] a5 a0 [2] 9a bc }

  condition:
    any of them
}