rule TTP_XOR_WriteProcessMemory_6cff {
  strings:
    $key_6cff = { 3b 8d [2] 09 af [2] 0f 9a [2] 21 9a [2] 1e 86 }

  condition:
    any of them
}