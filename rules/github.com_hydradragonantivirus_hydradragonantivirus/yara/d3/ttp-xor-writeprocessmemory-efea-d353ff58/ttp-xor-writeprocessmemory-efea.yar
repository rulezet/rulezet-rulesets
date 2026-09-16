rule TTP_XOR_WriteProcessMemory_efea {
  strings:
    $key_efea = { b8 98 [2] 8a ba [2] 8c 8f [2] a2 8f [2] 9d 93 }

  condition:
    any of them
}