rule TTP_XOR_WriteProcessMemory_6f0a {
  strings:
    $key_6f0a = { 38 78 [2] 0a 5a [2] 0c 6f [2] 22 6f [2] 1d 73 }

  condition:
    any of them
}