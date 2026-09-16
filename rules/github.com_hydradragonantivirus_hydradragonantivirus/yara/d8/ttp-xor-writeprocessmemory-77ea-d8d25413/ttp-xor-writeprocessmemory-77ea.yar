rule TTP_XOR_WriteProcessMemory_77ea {
  strings:
    $key_77ea = { 20 98 [2] 12 ba [2] 14 8f [2] 3a 8f [2] 05 93 }

  condition:
    any of them
}