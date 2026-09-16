rule TTP_XOR_WriteProcessMemory_49ea {
  strings:
    $key_49ea = { 1e 98 [2] 2c ba [2] 2a 8f [2] 04 8f [2] 3b 93 }

  condition:
    any of them
}