rule TTP_XOR_WriteProcessMemory_5f0a {
  strings:
    $key_5f0a = { 08 78 [2] 3a 5a [2] 3c 6f [2] 12 6f [2] 2d 73 }

  condition:
    any of them
}