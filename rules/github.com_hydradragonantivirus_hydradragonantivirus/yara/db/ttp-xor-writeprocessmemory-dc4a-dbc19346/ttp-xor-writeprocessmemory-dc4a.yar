rule TTP_XOR_WriteProcessMemory_dc4a {
  strings:
    $key_dc4a = { 8b 38 [2] b9 1a [2] bf 2f [2] 91 2f [2] ae 33 }

  condition:
    any of them
}