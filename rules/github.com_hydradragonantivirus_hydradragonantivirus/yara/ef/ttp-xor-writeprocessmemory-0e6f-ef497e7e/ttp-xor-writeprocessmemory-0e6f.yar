rule TTP_XOR_WriteProcessMemory_0e6f {
  strings:
    $key_0e6f = { 59 1d [2] 6b 3f [2] 6d 0a [2] 43 0a [2] 7c 16 }

  condition:
    any of them
}