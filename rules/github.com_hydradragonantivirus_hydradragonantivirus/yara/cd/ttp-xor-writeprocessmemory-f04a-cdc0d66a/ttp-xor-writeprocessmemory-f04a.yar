rule TTP_XOR_WriteProcessMemory_f04a {
  strings:
    $key_f04a = { a7 38 [2] 95 1a [2] 93 2f [2] bd 2f [2] 82 33 }

  condition:
    any of them
}