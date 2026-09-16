rule TTP_XOR_WriteProcessMemory_154a {
  strings:
    $key_154a = { 42 38 [2] 70 1a [2] 76 2f [2] 58 2f [2] 67 33 }

  condition:
    any of them
}