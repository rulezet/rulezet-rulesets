rule TTP_XOR_WriteProcessMemory_715a {
  strings:
    $key_715a = { 26 28 [2] 14 0a [2] 12 3f [2] 3c 3f [2] 03 23 }

  condition:
    any of them
}