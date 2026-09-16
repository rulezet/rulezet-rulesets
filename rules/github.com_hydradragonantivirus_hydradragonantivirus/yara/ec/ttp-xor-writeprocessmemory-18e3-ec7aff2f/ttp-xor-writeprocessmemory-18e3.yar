rule TTP_XOR_WriteProcessMemory_18e3 {
  strings:
    $key_18e3 = { 4f 91 [2] 7d b3 [2] 7b 86 [2] 55 86 [2] 6a 9a }

  condition:
    any of them
}