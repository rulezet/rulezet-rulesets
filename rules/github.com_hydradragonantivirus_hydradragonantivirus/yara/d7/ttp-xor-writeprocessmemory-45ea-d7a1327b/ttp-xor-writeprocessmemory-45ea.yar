rule TTP_XOR_WriteProcessMemory_45ea {
  strings:
    $key_45ea = { 12 98 [2] 20 ba [2] 26 8f [2] 08 8f [2] 37 93 }

  condition:
    any of them
}