rule TTP_XOR_WriteProcessMemory_2eac {
  strings:
    $key_2eac = { 79 de [2] 4b fc [2] 4d c9 [2] 63 c9 [2] 5c d5 }

  condition:
    any of them
}