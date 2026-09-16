rule TTP_XOR_WriteProcessMemory_725a {
  strings:
    $key_725a = { 25 28 [2] 17 0a [2] 11 3f [2] 3f 3f [2] 00 23 }

  condition:
    any of them
}