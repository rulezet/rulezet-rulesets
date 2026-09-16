rule TTP_XOR_WriteProcessMemory_637a {
  strings:
    $key_637a = { 34 08 [2] 06 2a [2] 00 1f [2] 2e 1f [2] 11 03 }

  condition:
    any of them
}