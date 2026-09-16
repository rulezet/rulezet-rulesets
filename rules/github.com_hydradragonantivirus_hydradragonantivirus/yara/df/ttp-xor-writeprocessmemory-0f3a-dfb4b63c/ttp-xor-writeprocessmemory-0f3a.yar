rule TTP_XOR_WriteProcessMemory_0f3a {
  strings:
    $key_0f3a = { 58 48 [2] 6a 6a [2] 6c 5f [2] 42 5f [2] 7d 43 }

  condition:
    any of them
}