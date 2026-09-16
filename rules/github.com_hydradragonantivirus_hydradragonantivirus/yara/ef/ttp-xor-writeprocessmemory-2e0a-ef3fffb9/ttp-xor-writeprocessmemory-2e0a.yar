rule TTP_XOR_WriteProcessMemory_2e0a {
  strings:
    $key_2e0a = { 79 78 [2] 4b 5a [2] 4d 6f [2] 63 6f [2] 5c 73 }

  condition:
    any of them
}