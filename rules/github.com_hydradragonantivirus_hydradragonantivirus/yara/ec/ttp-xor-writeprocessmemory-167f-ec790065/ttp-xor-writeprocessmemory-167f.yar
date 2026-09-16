rule TTP_XOR_WriteProcessMemory_167f {
  strings:
    $key_167f = { 41 0d [2] 73 2f [2] 75 1a [2] 5b 1a [2] 64 06 }

  condition:
    any of them
}