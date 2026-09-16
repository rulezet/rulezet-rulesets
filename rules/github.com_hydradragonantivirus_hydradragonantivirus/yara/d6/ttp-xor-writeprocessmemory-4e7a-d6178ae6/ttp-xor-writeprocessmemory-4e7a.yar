rule TTP_XOR_WriteProcessMemory_4e7a {
  strings:
    $key_4e7a = { 19 08 [2] 2b 2a [2] 2d 1f [2] 03 1f [2] 3c 03 }

  condition:
    any of them
}