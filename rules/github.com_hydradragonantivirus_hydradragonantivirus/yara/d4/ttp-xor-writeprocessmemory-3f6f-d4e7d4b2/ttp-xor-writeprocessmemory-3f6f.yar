rule TTP_XOR_WriteProcessMemory_3f6f {
  strings:
    $key_3f6f = { 68 1d [2] 5a 3f [2] 5c 0a [2] 72 0a [2] 4d 16 }

  condition:
    any of them
}