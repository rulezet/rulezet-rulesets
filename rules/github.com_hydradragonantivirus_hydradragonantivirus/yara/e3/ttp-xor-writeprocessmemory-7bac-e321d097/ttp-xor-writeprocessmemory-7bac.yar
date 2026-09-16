rule TTP_XOR_WriteProcessMemory_7bac {
  strings:
    $key_7bac = { 2c de [2] 1e fc [2] 18 c9 [2] 36 c9 [2] 09 d5 }

  condition:
    any of them
}