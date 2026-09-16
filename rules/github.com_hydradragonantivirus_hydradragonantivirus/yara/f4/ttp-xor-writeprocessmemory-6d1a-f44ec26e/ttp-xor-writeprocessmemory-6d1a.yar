rule TTP_XOR_WriteProcessMemory_6d1a {
  strings:
    $key_6d1a = { 3a 68 [2] 08 4a [2] 0e 7f [2] 20 7f [2] 1f 63 }

  condition:
    any of them
}