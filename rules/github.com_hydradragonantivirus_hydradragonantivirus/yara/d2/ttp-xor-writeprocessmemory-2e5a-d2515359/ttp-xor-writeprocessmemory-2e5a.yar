rule TTP_XOR_WriteProcessMemory_2e5a {
  strings:
    $key_2e5a = { 79 28 [2] 4b 0a [2] 4d 3f [2] 63 3f [2] 5c 23 }

  condition:
    any of them
}