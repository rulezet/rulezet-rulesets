rule TTP_XOR_WriteProcessMemory_504a {
  strings:
    $key_504a = { 07 38 [2] 35 1a [2] 33 2f [2] 1d 2f [2] 22 33 }

  condition:
    any of them
}