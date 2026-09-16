rule TTP_XOR_WriteProcessMemory_5f7a {
  strings:
    $key_5f7a = { 08 08 [2] 3a 2a [2] 3c 1f [2] 12 1f [2] 2d 03 }

  condition:
    any of them
}