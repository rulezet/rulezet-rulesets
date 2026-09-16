rule TTP_XOR_WriteProcessMemory_79ea {
  strings:
    $key_79ea = { 2e 98 [2] 1c ba [2] 1a 8f [2] 34 8f [2] 0b 93 }

  condition:
    any of them
}