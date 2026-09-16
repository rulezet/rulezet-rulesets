rule TTP_XOR_WriteProcessMemory_64ee {
  strings:
    $key_64ee = { 33 9c [2] 01 be [2] 07 8b [2] 29 8b [2] 16 97 }

  condition:
    any of them
}