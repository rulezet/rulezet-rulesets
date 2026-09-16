rule TTP_XOR_WriteProcessMemory_f01a {
  strings:
    $key_f01a = { a7 68 [2] 95 4a [2] 93 7f [2] bd 7f [2] 82 63 }

  condition:
    any of them
}