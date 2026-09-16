rule TTP_XOR_WriteProcessMemory_6f0f {
  strings:
    $key_6f0f = { 38 7d [2] 0a 5f [2] 0c 6a [2] 22 6a [2] 1d 76 }

  condition:
    any of them
}