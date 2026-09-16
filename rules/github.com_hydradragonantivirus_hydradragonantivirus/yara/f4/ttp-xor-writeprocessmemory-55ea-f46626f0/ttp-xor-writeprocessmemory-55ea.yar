rule TTP_XOR_WriteProcessMemory_55ea {
  strings:
    $key_55ea = { 02 98 [2] 30 ba [2] 36 8f [2] 18 8f [2] 27 93 }

  condition:
    any of them
}