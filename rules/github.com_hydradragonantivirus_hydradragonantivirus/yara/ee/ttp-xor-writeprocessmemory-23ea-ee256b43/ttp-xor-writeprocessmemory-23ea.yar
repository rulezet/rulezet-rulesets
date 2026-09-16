rule TTP_XOR_WriteProcessMemory_23ea {
  strings:
    $key_23ea = { 74 98 [2] 46 ba [2] 40 8f [2] 6e 8f [2] 51 93 }

  condition:
    any of them
}