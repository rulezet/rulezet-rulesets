rule TTP_XOR_WriteProcessMemory_600a {
  strings:
    $key_600a = { 37 78 [2] 05 5a [2] 03 6f [2] 2d 6f [2] 12 73 }

  condition:
    any of them
}