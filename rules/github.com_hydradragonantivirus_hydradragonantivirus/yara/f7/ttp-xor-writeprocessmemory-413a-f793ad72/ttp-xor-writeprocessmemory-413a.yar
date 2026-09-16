rule TTP_XOR_WriteProcessMemory_413a {
  strings:
    $key_413a = { 16 48 [2] 24 6a [2] 22 5f [2] 0c 5f [2] 33 43 }

  condition:
    any of them
}