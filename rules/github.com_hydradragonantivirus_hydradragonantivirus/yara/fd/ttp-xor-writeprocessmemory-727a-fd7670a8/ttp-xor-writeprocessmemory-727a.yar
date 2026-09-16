rule TTP_XOR_WriteProcessMemory_727a {
  strings:
    $key_727a = { 25 08 [2] 17 2a [2] 11 1f [2] 3f 1f [2] 00 03 }

  condition:
    any of them
}