rule TTP_XOR_WriteProcessMemory_304a {
  strings:
    $key_304a = { 67 38 [2] 55 1a [2] 53 2f [2] 7d 2f [2] 42 33 }

  condition:
    any of them
}