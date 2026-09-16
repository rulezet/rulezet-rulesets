rule TTP_XOR_WriteProcessMemory_3e3a {
  strings:
    $key_3e3a = { 69 48 [2] 5b 6a [2] 5d 5f [2] 73 5f [2] 4c 43 }

  condition:
    any of them
}