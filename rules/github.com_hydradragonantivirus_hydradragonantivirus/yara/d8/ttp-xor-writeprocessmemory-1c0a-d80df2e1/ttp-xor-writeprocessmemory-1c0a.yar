rule TTP_XOR_WriteProcessMemory_1c0a {
  strings:
    $key_1c0a = { 4b 78 [2] 79 5a [2] 7f 6f [2] 51 6f [2] 6e 73 }

  condition:
    any of them
}