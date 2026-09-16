rule TTP_XOR_WriteProcessMemory_7e1a {
  strings:
    $key_7e1a = { 29 68 [2] 1b 4a [2] 1d 7f [2] 33 7f [2] 0c 63 }

  condition:
    any of them
}