rule TTP_XOR_WriteProcessMemory_6b6a {
  strings:
    $key_6b6a = { 3c 18 [2] 0e 3a [2] 08 0f [2] 26 0f [2] 19 13 }

  condition:
    any of them
}