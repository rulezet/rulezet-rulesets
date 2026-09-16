rule TTP_XOR_WriteProcessMemory_0d1a {
  strings:
    $key_0d1a = { 5a 68 [2] 68 4a [2] 6e 7f [2] 40 7f [2] 7f 63 }

  condition:
    any of them
}