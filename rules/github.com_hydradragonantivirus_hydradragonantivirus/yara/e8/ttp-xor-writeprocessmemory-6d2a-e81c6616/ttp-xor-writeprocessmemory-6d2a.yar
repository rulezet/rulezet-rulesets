rule TTP_XOR_WriteProcessMemory_6d2a {
  strings:
    $key_6d2a = { 3a 58 [2] 08 7a [2] 0e 4f [2] 20 4f [2] 1f 53 }

  condition:
    any of them
}