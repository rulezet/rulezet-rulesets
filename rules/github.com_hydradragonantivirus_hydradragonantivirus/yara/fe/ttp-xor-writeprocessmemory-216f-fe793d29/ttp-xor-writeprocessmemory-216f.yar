rule TTP_XOR_WriteProcessMemory_216f {
  strings:
    $key_216f = { 76 1d [2] 44 3f [2] 42 0a [2] 6c 0a [2] 53 16 }

  condition:
    any of them
}