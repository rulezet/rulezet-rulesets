rule TTP_XOR_WriteProcessMemory_e240 {
  strings:
    $key_e240 = { b5 32 [2] 87 10 [2] 81 25 [2] af 25 [2] 90 39 }

  condition:
    any of them
}