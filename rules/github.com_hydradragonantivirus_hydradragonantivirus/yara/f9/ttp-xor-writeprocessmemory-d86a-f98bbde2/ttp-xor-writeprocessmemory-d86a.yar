rule TTP_XOR_WriteProcessMemory_d86a {
  strings:
    $key_d86a = { 8f 18 [2] bd 3a [2] bb 0f [2] 95 0f [2] aa 13 }

  condition:
    any of them
}