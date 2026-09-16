rule TTP_XOR_WriteProcessMemory_405a {
  strings:
    $key_405a = { 17 28 [2] 25 0a [2] 23 3f [2] 0d 3f [2] 32 23 }

  condition:
    any of them
}