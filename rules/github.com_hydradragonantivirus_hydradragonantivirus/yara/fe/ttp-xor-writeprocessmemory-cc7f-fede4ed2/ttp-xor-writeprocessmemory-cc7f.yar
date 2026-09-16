rule TTP_XOR_WriteProcessMemory_cc7f {
  strings:
    $key_cc7f = { 9b 0d [2] a9 2f [2] af 1a [2] 81 1a [2] be 06 }

  condition:
    any of them
}