rule TTP_XOR_WriteProcessMemory_2331 {
  strings:
    $key_2331 = { 74 43 [2] 46 61 [2] 40 54 [2] 6e 54 [2] 51 48 }

  condition:
    any of them
}