rule TTP_XOR_WriteProcessMemory_25ea {
  strings:
    $key_25ea = { 72 98 [2] 40 ba [2] 46 8f [2] 68 8f [2] 57 93 }

  condition:
    any of them
}