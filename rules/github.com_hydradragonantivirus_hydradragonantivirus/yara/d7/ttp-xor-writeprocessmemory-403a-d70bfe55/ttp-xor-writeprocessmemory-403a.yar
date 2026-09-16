rule TTP_XOR_WriteProcessMemory_403a {
  strings:
    $key_403a = { 17 48 [2] 25 6a [2] 23 5f [2] 0d 5f [2] 32 43 }

  condition:
    any of them
}