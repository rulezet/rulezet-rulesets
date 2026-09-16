rule TTP_XOR_WriteProcessMemory_6d6a {
  strings:
    $key_6d6a = { 3a 18 [2] 08 3a [2] 0e 0f [2] 20 0f [2] 1f 13 }

  condition:
    any of them
}