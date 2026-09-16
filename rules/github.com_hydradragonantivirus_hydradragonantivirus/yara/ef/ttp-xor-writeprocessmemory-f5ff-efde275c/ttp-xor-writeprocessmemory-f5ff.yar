rule TTP_XOR_WriteProcessMemory_f5ff {
  strings:
    $key_f5ff = { a2 8d [2] 90 af [2] 96 9a [2] b8 9a [2] 87 86 }

  condition:
    any of them
}