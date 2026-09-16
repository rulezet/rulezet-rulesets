rule TTP_XOR_WriteProcessMemory_0d6f {
  strings:
    $key_0d6f = { 5a 1d [2] 68 3f [2] 6e 0a [2] 40 0a [2] 7f 16 }

  condition:
    any of them
}