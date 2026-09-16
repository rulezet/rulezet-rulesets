rule TTP_XOR_WriteProcessMemory_0f5a {
  strings:
    $key_0f5a = { 58 28 [2] 6a 0a [2] 6c 3f [2] 42 3f [2] 7d 23 }

  condition:
    any of them
}