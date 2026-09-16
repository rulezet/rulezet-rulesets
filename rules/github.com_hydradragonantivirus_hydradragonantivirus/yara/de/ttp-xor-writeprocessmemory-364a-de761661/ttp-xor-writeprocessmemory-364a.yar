rule TTP_XOR_WriteProcessMemory_364a {
  strings:
    $key_364a = { 61 38 [2] 53 1a [2] 55 2f [2] 7b 2f [2] 44 33 }

  condition:
    any of them
}