rule TTP_XOR_WriteProcessMemory_0b1f {
  strings:
    $key_0b1f = { 5c 6d [2] 6e 4f [2] 68 7a [2] 46 7a [2] 79 66 }

  condition:
    any of them
}