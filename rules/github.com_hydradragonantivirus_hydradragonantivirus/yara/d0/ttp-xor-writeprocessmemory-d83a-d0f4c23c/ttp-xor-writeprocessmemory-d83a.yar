rule TTP_XOR_WriteProcessMemory_d83a {
  strings:
    $key_d83a = { 8f 48 [2] bd 6a [2] bb 5f [2] 95 5f [2] aa 43 }

  condition:
    any of them
}