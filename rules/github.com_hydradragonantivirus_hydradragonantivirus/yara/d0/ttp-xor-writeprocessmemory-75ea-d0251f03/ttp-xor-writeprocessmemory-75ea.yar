rule TTP_XOR_WriteProcessMemory_75ea {
  strings:
    $key_75ea = { 22 98 [2] 10 ba [2] 16 8f [2] 38 8f [2] 07 93 }

  condition:
    any of them
}