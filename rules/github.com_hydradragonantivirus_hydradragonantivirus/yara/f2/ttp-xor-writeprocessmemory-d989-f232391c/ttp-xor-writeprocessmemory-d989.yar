rule TTP_XOR_WriteProcessMemory_d989 {
  strings:
    $key_d989 = { 8e fb [2] bc d9 [2] ba ec [2] 94 ec [2] ab f0 }

  condition:
    any of them
}