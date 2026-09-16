rule TTP_XOR_WriteProcessMemory_3c4a {
  strings:
    $key_3c4a = { 6b 38 [2] 59 1a [2] 5f 2f [2] 71 2f [2] 4e 33 }

  condition:
    any of them
}