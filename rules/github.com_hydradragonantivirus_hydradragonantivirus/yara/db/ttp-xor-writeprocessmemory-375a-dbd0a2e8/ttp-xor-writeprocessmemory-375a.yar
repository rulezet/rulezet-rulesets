rule TTP_XOR_WriteProcessMemory_375a {
  strings:
    $key_375a = { 60 28 [2] 52 0a [2] 54 3f [2] 7a 3f [2] 45 23 }

  condition:
    any of them
}