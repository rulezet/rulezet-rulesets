rule TTP_XOR_WriteProcessMemory_7c5a {
  strings:
    $key_7c5a = { 2b 28 [2] 19 0a [2] 1f 3f [2] 31 3f [2] 0e 23 }

  condition:
    any of them
}