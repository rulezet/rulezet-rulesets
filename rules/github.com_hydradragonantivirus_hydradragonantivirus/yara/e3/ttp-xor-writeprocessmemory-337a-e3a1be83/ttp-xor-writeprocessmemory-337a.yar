rule TTP_XOR_WriteProcessMemory_337a {
  strings:
    $key_337a = { 64 08 [2] 56 2a [2] 50 1f [2] 7e 1f [2] 41 03 }

  condition:
    any of them
}