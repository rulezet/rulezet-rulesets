rule TTP_XOR_WriteProcessMemory_cc1f {
  strings:
    $key_cc1f = { 9b 6d [2] a9 4f [2] af 7a [2] 81 7a [2] be 66 }

  condition:
    any of them
}