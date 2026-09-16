rule TTP_XOR_WriteProcessMemory_093a {
  strings:
    $key_093a = { 5e 48 [2] 6c 6a [2] 6a 5f [2] 44 5f [2] 7b 43 }

  condition:
    any of them
}