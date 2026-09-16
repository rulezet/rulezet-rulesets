rule TTP_XOR_WriteProcessMemory_7b6a {
  strings:
    $key_7b6a = { 2c 18 [2] 1e 3a [2] 18 0f [2] 36 0f [2] 09 13 }

  condition:
    any of them
}