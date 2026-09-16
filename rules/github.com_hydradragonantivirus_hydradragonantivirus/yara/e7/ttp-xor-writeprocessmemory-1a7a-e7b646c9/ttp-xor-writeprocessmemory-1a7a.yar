rule TTP_XOR_WriteProcessMemory_1a7a {
  strings:
    $key_1a7a = { 4d 08 [2] 7f 2a [2] 79 1f [2] 57 1f [2] 68 03 }

  condition:
    any of them
}