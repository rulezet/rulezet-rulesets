rule TTP_XOR_WriteProcessMemory_7b5a {
  strings:
    $key_7b5a = { 2c 28 [2] 1e 0a [2] 18 3f [2] 36 3f [2] 09 23 }

  condition:
    any of them
}