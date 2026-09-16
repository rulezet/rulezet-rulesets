rule TTP_XOR_WriteProcessMemory_1aff {
  strings:
    $key_1aff = { 4d 8d [2] 7f af [2] 79 9a [2] 57 9a [2] 68 86 }

  condition:
    any of them
}