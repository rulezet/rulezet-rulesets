rule TTP_XOR_WriteProcessMemory_4bff {
  strings:
    $key_4bff = { 1c 8d [2] 2e af [2] 28 9a [2] 06 9a [2] 39 86 }

  condition:
    any of them
}