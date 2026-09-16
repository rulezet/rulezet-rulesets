rule TTP_XOR_WriteProcessMemory_e9ac {
  strings:
    $key_e9ac = { be de [2] 8c fc [2] 8a c9 [2] a4 c9 [2] 9b d5 }

  condition:
    any of them
}