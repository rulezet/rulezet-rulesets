rule TTP_XOR_WriteProcessMemory_666a {
  strings:
    $key_666a = { 31 18 [2] 03 3a [2] 05 0f [2] 2b 0f [2] 14 13 }

  condition:
    any of them
}