rule TTP_XOR_WriteProcessMemory_f06a {
  strings:
    $key_f06a = { a7 18 [2] 95 3a [2] 93 0f [2] bd 0f [2] 82 13 }

  condition:
    any of them
}