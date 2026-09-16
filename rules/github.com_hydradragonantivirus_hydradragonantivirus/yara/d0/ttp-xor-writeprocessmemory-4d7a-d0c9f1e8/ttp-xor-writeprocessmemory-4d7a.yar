rule TTP_XOR_WriteProcessMemory_4d7a {
  strings:
    $key_4d7a = { 1a 08 [2] 28 2a [2] 2e 1f [2] 00 1f [2] 3f 03 }

  condition:
    any of them
}