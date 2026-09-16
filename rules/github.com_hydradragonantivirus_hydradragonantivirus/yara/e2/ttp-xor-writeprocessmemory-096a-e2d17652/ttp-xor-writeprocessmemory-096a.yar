rule TTP_XOR_WriteProcessMemory_096a {
  strings:
    $key_096a = { 5e 18 [2] 6c 3a [2] 6a 0f [2] 44 0f [2] 7b 13 }

  condition:
    any of them
}