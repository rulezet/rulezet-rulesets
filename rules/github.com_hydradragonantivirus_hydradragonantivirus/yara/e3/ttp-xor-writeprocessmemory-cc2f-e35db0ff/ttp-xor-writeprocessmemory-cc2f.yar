rule TTP_XOR_WriteProcessMemory_cc2f {
  strings:
    $key_cc2f = { 9b 5d [2] a9 7f [2] af 4a [2] 81 4a [2] be 56 }

  condition:
    any of them
}