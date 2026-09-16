rule TTP_XOR_WriteProcessMemory_192a {
  strings:
    $key_192a = { 4e 58 [2] 7c 7a [2] 7a 4f [2] 54 4f [2] 6b 53 }

  condition:
    any of them
}