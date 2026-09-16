rule TTP_XOR_WriteProcessMemory_172d {
  strings:
    $key_172d = { 40 5f [2] 72 7d [2] 74 48 [2] 5a 48 [2] 65 54 }

  condition:
    any of them
}