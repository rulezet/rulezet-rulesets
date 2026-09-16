rule TTP_XOR_WriteProcessMemory_1a5a {
  strings:
    $key_1a5a = { 4d 28 [2] 7f 0a [2] 79 3f [2] 57 3f [2] 68 23 }

  condition:
    any of them
}