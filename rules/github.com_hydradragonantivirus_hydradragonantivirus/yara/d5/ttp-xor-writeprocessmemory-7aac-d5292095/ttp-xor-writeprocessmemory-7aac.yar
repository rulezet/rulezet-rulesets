rule TTP_XOR_WriteProcessMemory_7aac {
  strings:
    $key_7aac = { 2d de [2] 1f fc [2] 19 c9 [2] 37 c9 [2] 08 d5 }

  condition:
    any of them
}