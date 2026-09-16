rule TTP_XOR_WriteProcessMemory_6f5a {
  strings:
    $key_6f5a = { 38 28 [2] 0a 0a [2] 0c 3f [2] 22 3f [2] 1d 23 }

  condition:
    any of them
}