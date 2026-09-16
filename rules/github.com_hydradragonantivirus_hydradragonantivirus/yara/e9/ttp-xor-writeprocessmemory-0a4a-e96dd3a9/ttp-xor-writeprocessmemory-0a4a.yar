rule TTP_XOR_WriteProcessMemory_0a4a {
  strings:
    $key_0a4a = { 5d 38 [2] 6f 1a [2] 69 2f [2] 47 2f [2] 78 33 }

  condition:
    any of them
}