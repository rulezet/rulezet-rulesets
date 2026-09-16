rule TTP_XOR_WriteProcessMemory_677f {
  strings:
    $key_677f = { 30 0d [2] 02 2f [2] 04 1a [2] 2a 1a [2] 15 06 }

  condition:
    any of them
}