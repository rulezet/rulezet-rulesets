rule TTP_XOR_WriteProcessMemory_5d5a {
  strings:
    $key_5d5a = { 0a 28 [2] 38 0a [2] 3e 3f [2] 10 3f [2] 2f 23 }

  condition:
    any of them
}