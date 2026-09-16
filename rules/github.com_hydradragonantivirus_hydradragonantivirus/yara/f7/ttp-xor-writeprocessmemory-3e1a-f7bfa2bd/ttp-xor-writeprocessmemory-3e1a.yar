rule TTP_XOR_WriteProcessMemory_3e1a {
  strings:
    $key_3e1a = { 69 68 [2] 5b 4a [2] 5d 7f [2] 73 7f [2] 4c 63 }

  condition:
    any of them
}