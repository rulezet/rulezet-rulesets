rule TTP_XOR_WriteProcessMemory_4e2a {
  strings:
    $key_4e2a = { 19 58 [2] 2b 7a [2] 2d 4f [2] 03 4f [2] 3c 53 }

  condition:
    any of them
}