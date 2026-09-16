rule TTP_XOR_WriteProcessMemory_27ea {
  strings:
    $key_27ea = { 70 98 [2] 42 ba [2] 44 8f [2] 6a 8f [2] 55 93 }

  condition:
    any of them
}