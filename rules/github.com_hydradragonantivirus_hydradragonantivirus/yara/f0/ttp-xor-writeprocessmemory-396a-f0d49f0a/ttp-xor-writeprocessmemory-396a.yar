rule TTP_XOR_WriteProcessMemory_396a {
  strings:
    $key_396a = { 6e 18 [2] 5c 3a [2] 5a 0f [2] 74 0f [2] 4b 13 }

  condition:
    any of them
}