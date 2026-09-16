rule TTP_XOR_WriteProcessMemory_29ac {
  strings:
    $key_29ac = { 7e de [2] 4c fc [2] 4a c9 [2] 64 c9 [2] 5b d5 }

  condition:
    any of them
}