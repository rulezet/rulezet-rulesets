rule TTP_XOR_WriteProcessMemory_516f {
  strings:
    $key_516f = { 06 1d [2] 34 3f [2] 32 0a [2] 1c 0a [2] 23 16 }

  condition:
    any of them
}