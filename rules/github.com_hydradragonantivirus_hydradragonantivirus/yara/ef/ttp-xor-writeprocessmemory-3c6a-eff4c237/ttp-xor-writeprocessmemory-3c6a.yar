rule TTP_XOR_WriteProcessMemory_3c6a {
  strings:
    $key_3c6a = { 6b 18 [2] 59 3a [2] 5f 0f [2] 71 0f [2] 4e 13 }

  condition:
    any of them
}