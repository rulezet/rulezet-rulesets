rule TTP_XOR_WriteProcessMemory_1c4a {
  strings:
    $key_1c4a = { 4b 38 [2] 79 1a [2] 7f 2f [2] 51 2f [2] 6e 33 }

  condition:
    any of them
}