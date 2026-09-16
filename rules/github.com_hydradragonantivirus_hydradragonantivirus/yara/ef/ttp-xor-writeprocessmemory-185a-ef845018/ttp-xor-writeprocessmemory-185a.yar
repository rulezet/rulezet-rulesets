rule TTP_XOR_WriteProcessMemory_185a {
  strings:
    $key_185a = { 4f 28 [2] 7d 0a [2] 7b 3f [2] 55 3f [2] 6a 23 }

  condition:
    any of them
}