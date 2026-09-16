rule TTP_XOR_WriteProcessMemory_276a {
  strings:
    $key_276a = { 70 18 [2] 42 3a [2] 44 0f [2] 6a 0f [2] 55 13 }

  condition:
    any of them
}