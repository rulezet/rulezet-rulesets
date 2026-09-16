rule TTP_XOR_WriteProcessMemory_6bff {
  strings:
    $key_6bff = { 3c 8d [2] 0e af [2] 08 9a [2] 26 9a [2] 19 86 }

  condition:
    any of them
}