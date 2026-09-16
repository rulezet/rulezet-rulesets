rule TTP_XOR_WriteProcessMemory_505a {
  strings:
    $key_505a = { 07 28 [2] 35 0a [2] 33 3f [2] 1d 3f [2] 22 23 }

  condition:
    any of them
}