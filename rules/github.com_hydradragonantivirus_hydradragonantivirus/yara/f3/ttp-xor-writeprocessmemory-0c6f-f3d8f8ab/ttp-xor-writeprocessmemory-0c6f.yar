rule TTP_XOR_WriteProcessMemory_0c6f {
  strings:
    $key_0c6f = { 5b 1d [2] 69 3f [2] 6f 0a [2] 41 0a [2] 7e 16 }

  condition:
    any of them
}