rule TTP_XOR_WriteProcessMemory_6b2a {
  strings:
    $key_6b2a = { 3c 58 [2] 0e 7a [2] 08 4f [2] 26 4f [2] 19 53 }

  condition:
    any of them
}