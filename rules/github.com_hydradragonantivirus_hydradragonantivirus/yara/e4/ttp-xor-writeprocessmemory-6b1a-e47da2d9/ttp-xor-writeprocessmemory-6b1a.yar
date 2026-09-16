rule TTP_XOR_WriteProcessMemory_6b1a {
  strings:
    $key_6b1a = { 3c 68 [2] 0e 4a [2] 08 7f [2] 26 7f [2] 19 63 }

  condition:
    any of them
}