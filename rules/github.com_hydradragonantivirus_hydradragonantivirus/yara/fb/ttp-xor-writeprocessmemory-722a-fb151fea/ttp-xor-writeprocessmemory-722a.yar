rule TTP_XOR_WriteProcessMemory_722a {
  strings:
    $key_722a = { 25 58 [2] 17 7a [2] 11 4f [2] 3f 4f [2] 00 53 }

  condition:
    any of them
}