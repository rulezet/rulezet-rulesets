rule TTP_XOR_WriteProcessMemory_710a {
  strings:
    $key_710a = { 26 78 [2] 14 5a [2] 12 6f [2] 3c 6f [2] 03 73 }

  condition:
    any of them
}