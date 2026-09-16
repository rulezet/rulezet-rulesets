rule TTP_XOR_WriteProcessMemory_2c2a {
  strings:
    $key_2c2a = { 7b 58 [2] 49 7a [2] 4f 4f [2] 61 4f [2] 5e 53 }

  condition:
    any of them
}