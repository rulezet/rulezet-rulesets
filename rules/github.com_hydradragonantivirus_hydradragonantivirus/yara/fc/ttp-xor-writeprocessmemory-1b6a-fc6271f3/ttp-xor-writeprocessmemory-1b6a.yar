rule TTP_XOR_WriteProcessMemory_1b6a {
  strings:
    $key_1b6a = { 4c 18 [2] 7e 3a [2] 78 0f [2] 56 0f [2] 69 13 }

  condition:
    any of them
}