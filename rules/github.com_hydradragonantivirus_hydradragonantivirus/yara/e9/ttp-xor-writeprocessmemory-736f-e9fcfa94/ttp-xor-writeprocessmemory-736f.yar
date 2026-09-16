rule TTP_XOR_WriteProcessMemory_736f {
  strings:
    $key_736f = { 24 1d [2] 16 3f [2] 10 0a [2] 3e 0a [2] 01 16 }

  condition:
    any of them
}