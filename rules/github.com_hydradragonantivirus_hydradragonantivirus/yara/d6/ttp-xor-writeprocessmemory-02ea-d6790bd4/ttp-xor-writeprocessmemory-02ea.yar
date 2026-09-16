rule TTP_XOR_WriteProcessMemory_02ea {
  strings:
    $key_02ea = { 55 98 [2] 67 ba [2] 61 8f [2] 4f 8f [2] 70 93 }

  condition:
    any of them
}