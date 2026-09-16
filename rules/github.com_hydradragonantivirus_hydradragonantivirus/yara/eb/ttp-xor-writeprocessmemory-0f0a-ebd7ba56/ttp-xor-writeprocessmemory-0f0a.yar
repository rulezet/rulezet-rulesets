rule TTP_XOR_WriteProcessMemory_0f0a {
  strings:
    $key_0f0a = { 58 78 [2] 6a 5a [2] 6c 6f [2] 42 6f [2] 7d 73 }

  condition:
    any of them
}