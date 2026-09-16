rule TTP_XOR_WriteProcessMemory_7f5a {
  strings:
    $key_7f5a = { 28 28 [2] 1a 0a [2] 1c 3f [2] 32 3f [2] 0d 23 }

  condition:
    any of them
}