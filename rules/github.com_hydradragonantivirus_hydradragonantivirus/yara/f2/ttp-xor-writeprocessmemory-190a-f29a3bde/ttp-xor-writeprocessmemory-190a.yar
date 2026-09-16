rule TTP_XOR_WriteProcessMemory_190a {
  strings:
    $key_190a = { 4e 78 [2] 7c 5a [2] 7a 6f [2] 54 6f [2] 6b 73 }

  condition:
    any of them
}