rule TTP_XOR_WriteProcessMemory_460a {
  strings:
    $key_460a = { 11 78 [2] 23 5a [2] 25 6f [2] 0b 6f [2] 34 73 }

  condition:
    any of them
}