rule TTP_XOR_WriteProcessMemory_2c0a {
  strings:
    $key_2c0a = { 7b 78 [2] 49 5a [2] 4f 6f [2] 61 6f [2] 5e 73 }

  condition:
    any of them
}