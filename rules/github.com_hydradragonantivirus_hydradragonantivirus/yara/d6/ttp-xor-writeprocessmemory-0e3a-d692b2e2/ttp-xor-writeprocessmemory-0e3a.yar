rule TTP_XOR_WriteProcessMemory_0e3a {
  strings:
    $key_0e3a = { 59 48 [2] 6b 6a [2] 6d 5f [2] 43 5f [2] 7c 43 }

  condition:
    any of them
}