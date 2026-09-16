rule TTP_XOR_WriteProcessMemory_332a {
  strings:
    $key_332a = { 64 58 [2] 56 7a [2] 50 4f [2] 7e 4f [2] 41 53 }

  condition:
    any of them
}