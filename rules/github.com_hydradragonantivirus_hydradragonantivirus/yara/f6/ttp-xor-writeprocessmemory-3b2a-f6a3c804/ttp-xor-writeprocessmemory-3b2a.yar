rule TTP_XOR_WriteProcessMemory_3b2a {
  strings:
    $key_3b2a = { 6c 58 [2] 5e 7a [2] 58 4f [2] 76 4f [2] 49 53 }

  condition:
    any of them
}