rule TTP_XOR_WriteProcessMemory_5a2a {
  strings:
    $key_5a2a = { 0d 58 [2] 3f 7a [2] 39 4f [2] 17 4f [2] 28 53 }

  condition:
    any of them
}