rule TTP_XOR_WriteProcessMemory_4cff {
  strings:
    $key_4cff = { 1b 8d [2] 29 af [2] 2f 9a [2] 01 9a [2] 3e 86 }

  condition:
    any of them
}