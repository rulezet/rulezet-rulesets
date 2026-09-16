rule TTP_XOR_WriteProcessMemory_7d4a {
  strings:
    $key_7d4a = { 2a 38 [2] 18 1a [2] 1e 2f [2] 30 2f [2] 0f 33 }

  condition:
    any of them
}