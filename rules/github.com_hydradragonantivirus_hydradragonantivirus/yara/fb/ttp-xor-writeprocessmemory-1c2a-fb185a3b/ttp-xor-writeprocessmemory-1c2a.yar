rule TTP_XOR_WriteProcessMemory_1c2a {
  strings:
    $key_1c2a = { 4b 58 [2] 79 7a [2] 7f 4f [2] 51 4f [2] 6e 53 }

  condition:
    any of them
}