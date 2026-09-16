rule TTP_XOR_WriteProcessMemory_060a {
  strings:
    $key_060a = { 51 78 [2] 63 5a [2] 65 6f [2] 4b 6f [2] 74 73 }

  condition:
    any of them
}