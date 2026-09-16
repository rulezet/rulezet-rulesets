rule TTP_XOR_WriteProcessMemory_c9dd {
  strings:
    $key_c9dd = { 9e af [2] ac 8d [2] aa b8 [2] 84 b8 [2] bb a4 }

  condition:
    any of them
}