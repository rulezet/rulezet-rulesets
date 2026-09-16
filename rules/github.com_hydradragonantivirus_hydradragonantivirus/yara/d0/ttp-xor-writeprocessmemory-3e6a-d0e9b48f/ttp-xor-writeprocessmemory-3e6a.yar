rule TTP_XOR_WriteProcessMemory_3e6a {
  strings:
    $key_3e6a = { 69 18 [2] 5b 3a [2] 5d 0f [2] 73 0f [2] 4c 13 }

  condition:
    any of them
}