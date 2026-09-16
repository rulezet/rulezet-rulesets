rule TTP_XOR_WriteProcessMemory_cc7a {
  strings:
    $key_cc7a = { 9b 08 [2] a9 2a [2] af 1f [2] 81 1f [2] be 03 }

  condition:
    any of them
}