rule TTP_XOR_WriteProcessMemory_676a {
  strings:
    $key_676a = { 30 18 [2] 02 3a [2] 04 0f [2] 2a 0f [2] 15 13 }

  condition:
    any of them
}