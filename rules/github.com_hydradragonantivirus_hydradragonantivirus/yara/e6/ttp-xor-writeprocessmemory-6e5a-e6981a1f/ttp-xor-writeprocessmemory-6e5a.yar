rule TTP_XOR_WriteProcessMemory_6e5a {
  strings:
    $key_6e5a = { 39 28 [2] 0b 0a [2] 0d 3f [2] 23 3f [2] 1c 23 }

  condition:
    any of them
}