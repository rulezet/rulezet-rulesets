rule TTP_XOR_WriteProcessMemory_7c3a {
  strings:
    $key_7c3a = { 2b 48 [2] 19 6a [2] 1f 5f [2] 31 5f [2] 0e 43 }

  condition:
    any of them
}