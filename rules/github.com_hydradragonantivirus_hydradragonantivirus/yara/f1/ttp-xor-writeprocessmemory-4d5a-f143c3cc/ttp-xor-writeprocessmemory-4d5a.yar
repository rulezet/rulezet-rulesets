rule TTP_XOR_WriteProcessMemory_4d5a {
  strings:
    $key_4d5a = { 1a 28 [2] 28 0a [2] 2e 3f [2] 00 3f [2] 3f 23 }

  condition:
    any of them
}