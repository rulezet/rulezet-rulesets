rule TTP_XOR_WriteProcessMemory_257a {
  strings:
    $key_257a = { 72 08 [2] 40 2a [2] 46 1f [2] 68 1f [2] 57 03 }

  condition:
    any of them
}