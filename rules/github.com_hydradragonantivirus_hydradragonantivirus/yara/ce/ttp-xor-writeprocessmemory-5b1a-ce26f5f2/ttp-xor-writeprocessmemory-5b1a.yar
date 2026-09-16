rule TTP_XOR_WriteProcessMemory_5b1a {
  strings:
    $key_5b1a = { 0c 68 [2] 3e 4a [2] 38 7f [2] 16 7f [2] 29 63 }

  condition:
    any of them
}