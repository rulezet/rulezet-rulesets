rule TTP_XOR_WriteProcessMemory_063a {
  strings:
    $key_063a = { 51 48 [2] 63 6a [2] 65 5f [2] 4b 5f [2] 74 43 }

  condition:
    any of them
}