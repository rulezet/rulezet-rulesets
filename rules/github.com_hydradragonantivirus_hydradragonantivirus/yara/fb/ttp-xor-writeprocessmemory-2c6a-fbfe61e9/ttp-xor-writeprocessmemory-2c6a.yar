rule TTP_XOR_WriteProcessMemory_2c6a {
  strings:
    $key_2c6a = { 7b 18 [2] 49 3a [2] 4f 0f [2] 61 0f [2] 5e 13 }

  condition:
    any of them
}