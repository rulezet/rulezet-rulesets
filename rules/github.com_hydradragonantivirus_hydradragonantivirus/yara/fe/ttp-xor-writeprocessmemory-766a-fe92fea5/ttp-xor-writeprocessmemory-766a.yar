rule TTP_XOR_WriteProcessMemory_766a {
  strings:
    $key_766a = { 21 18 [2] 13 3a [2] 15 0f [2] 3b 0f [2] 04 13 }

  condition:
    any of them
}