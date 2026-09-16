rule TTP_XOR_WriteProcessMemory_5b3a {
  strings:
    $key_5b3a = { 0c 48 [2] 3e 6a [2] 38 5f [2] 16 5f [2] 29 43 }

  condition:
    any of them
}