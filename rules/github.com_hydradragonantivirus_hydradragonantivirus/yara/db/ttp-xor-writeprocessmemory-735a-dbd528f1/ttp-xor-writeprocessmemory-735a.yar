rule TTP_XOR_WriteProcessMemory_735a {
  strings:
    $key_735a = { 24 28 [2] 16 0a [2] 10 3f [2] 3e 3f [2] 01 23 }

  condition:
    any of them
}