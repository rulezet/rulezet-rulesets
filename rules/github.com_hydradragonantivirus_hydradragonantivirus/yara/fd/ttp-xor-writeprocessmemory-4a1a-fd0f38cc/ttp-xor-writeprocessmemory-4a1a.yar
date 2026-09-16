rule TTP_XOR_WriteProcessMemory_4a1a {
  strings:
    $key_4a1a = { 1d 68 [2] 2f 4a [2] 29 7f [2] 07 7f [2] 38 63 }

  condition:
    any of them
}