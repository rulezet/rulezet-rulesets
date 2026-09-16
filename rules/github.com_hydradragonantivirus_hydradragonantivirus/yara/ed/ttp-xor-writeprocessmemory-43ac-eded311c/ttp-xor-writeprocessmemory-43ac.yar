rule TTP_XOR_WriteProcessMemory_43ac {
  strings:
    $key_43ac = { 14 de [2] 26 fc [2] 20 c9 [2] 0e c9 [2] 31 d5 }

  condition:
    any of them
}