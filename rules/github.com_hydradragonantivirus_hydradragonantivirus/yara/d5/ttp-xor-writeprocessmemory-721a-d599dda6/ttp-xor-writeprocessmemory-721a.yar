rule TTP_XOR_WriteProcessMemory_721a {
  strings:
    $key_721a = { 25 68 [2] 17 4a [2] 11 7f [2] 3f 7f [2] 00 63 }

  condition:
    any of them
}