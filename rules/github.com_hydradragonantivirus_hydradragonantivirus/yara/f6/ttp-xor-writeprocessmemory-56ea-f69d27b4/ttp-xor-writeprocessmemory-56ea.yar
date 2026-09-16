rule TTP_XOR_WriteProcessMemory_56ea {
  strings:
    $key_56ea = { 01 98 [2] 33 ba [2] 35 8f [2] 1b 8f [2] 24 93 }

  condition:
    any of them
}