rule TTP_XOR_WriteProcessMemory_e226 {
  strings:
    $key_e226 = { b5 54 [2] 87 76 [2] 81 43 [2] af 43 [2] 90 5f }

  condition:
    any of them
}