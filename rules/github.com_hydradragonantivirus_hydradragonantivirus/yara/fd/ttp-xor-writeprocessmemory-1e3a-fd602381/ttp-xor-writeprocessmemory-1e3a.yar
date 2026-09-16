rule TTP_XOR_WriteProcessMemory_1e3a {
  strings:
    $key_1e3a = { 49 48 [2] 7b 6a [2] 7d 5f [2] 53 5f [2] 6c 43 }

  condition:
    any of them
}