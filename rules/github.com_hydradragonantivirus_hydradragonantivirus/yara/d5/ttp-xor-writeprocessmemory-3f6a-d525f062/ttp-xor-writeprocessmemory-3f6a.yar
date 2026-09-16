rule TTP_XOR_WriteProcessMemory_3f6a {
  strings:
    $key_3f6a = { 68 18 [2] 5a 3a [2] 5c 0f [2] 72 0f [2] 4d 13 }

  condition:
    any of them
}