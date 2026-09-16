rule TTP_XOR_WriteProcessMemory_7e6a {
  strings:
    $key_7e6a = { 29 18 [2] 1b 3a [2] 1d 0f [2] 33 0f [2] 0c 13 }

  condition:
    any of them
}