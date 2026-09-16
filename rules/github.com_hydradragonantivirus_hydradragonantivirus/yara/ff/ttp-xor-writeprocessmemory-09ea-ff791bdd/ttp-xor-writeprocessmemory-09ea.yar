rule TTP_XOR_WriteProcessMemory_09ea {
  strings:
    $key_09ea = { 5e 98 [2] 6c ba [2] 6a 8f [2] 44 8f [2] 7b 93 }

  condition:
    any of them
}