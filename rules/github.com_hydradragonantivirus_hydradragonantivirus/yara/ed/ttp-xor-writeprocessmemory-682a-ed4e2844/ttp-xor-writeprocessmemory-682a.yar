rule TTP_XOR_WriteProcessMemory_682a {
  strings:
    $key_682a = { 3f 58 [2] 0d 7a [2] 0b 4f [2] 25 4f [2] 1a 53 }

  condition:
    any of them
}