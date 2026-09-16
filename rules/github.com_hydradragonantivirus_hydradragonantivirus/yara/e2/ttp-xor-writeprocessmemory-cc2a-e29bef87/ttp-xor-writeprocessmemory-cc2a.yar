rule TTP_XOR_WriteProcessMemory_cc2a {
  strings:
    $key_cc2a = { 9b 58 [2] a9 7a [2] af 4f [2] 81 4f [2] be 53 }

  condition:
    any of them
}