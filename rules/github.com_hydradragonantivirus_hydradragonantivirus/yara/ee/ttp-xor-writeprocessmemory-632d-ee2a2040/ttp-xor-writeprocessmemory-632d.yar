rule TTP_XOR_WriteProcessMemory_632d {
  strings:
    $key_632d = { 34 5f [2] 06 7d [2] 00 48 [2] 2e 48 [2] 11 54 }

  condition:
    any of them
}