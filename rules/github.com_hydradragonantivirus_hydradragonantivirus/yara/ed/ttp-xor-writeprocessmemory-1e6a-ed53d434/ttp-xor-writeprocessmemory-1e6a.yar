rule TTP_XOR_WriteProcessMemory_1e6a {
  strings:
    $key_1e6a = { 49 18 [2] 7b 3a [2] 7d 0f [2] 53 0f [2] 6c 13 }

  condition:
    any of them
}