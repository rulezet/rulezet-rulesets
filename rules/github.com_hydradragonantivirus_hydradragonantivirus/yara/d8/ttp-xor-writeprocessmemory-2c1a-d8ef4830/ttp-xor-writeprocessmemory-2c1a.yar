rule TTP_XOR_WriteProcessMemory_2c1a {
  strings:
    $key_2c1a = { 7b 68 [2] 49 4a [2] 4f 7f [2] 61 7f [2] 5e 63 }

  condition:
    any of them
}