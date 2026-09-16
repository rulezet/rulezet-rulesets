rule TTP_XOR_WriteProcessMemory_0bff {
  strings:
    $key_0bff = { 5c 8d [2] 6e af [2] 68 9a [2] 46 9a [2] 79 86 }

  condition:
    any of them
}