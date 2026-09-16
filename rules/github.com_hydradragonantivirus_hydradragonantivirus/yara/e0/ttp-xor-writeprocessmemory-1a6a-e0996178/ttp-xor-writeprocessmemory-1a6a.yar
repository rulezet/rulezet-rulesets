rule TTP_XOR_WriteProcessMemory_1a6a {
  strings:
    $key_1a6a = { 4d 18 [2] 7f 3a [2] 79 0f [2] 57 0f [2] 68 13 }

  condition:
    any of them
}