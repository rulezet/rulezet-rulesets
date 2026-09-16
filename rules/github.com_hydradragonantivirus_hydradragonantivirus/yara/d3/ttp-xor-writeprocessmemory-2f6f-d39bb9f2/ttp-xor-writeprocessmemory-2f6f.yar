rule TTP_XOR_WriteProcessMemory_2f6f {
  strings:
    $key_2f6f = { 78 1d [2] 4a 3f [2] 4c 0a [2] 62 0a [2] 5d 16 }

  condition:
    any of them
}