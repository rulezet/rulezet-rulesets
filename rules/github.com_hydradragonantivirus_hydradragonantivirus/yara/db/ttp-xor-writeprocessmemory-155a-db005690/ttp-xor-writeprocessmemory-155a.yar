rule TTP_XOR_WriteProcessMemory_155a {
  strings:
    $key_155a = { 42 28 [2] 70 0a [2] 76 3f [2] 58 3f [2] 67 23 }

  condition:
    any of them
}