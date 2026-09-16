rule TTP_XOR_WriteProcessMemory_4e5a {
  strings:
    $key_4e5a = { 19 28 [2] 2b 0a [2] 2d 3f [2] 03 3f [2] 3c 23 }

  condition:
    any of them
}