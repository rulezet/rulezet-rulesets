rule TTP_XOR_WriteProcessMemory_1e5f {
  strings:
    $key_1e5f = { 49 2d [2] 7b 0f [2] 7d 3a [2] 53 3a [2] 6c 26 }

  condition:
    any of them
}