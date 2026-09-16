rule TTP_XOR_WriteProcessMemory_2a6a {
  strings:
    $key_2a6a = { 7d 18 [2] 4f 3a [2] 49 0f [2] 67 0f [2] 58 13 }

  condition:
    any of them
}