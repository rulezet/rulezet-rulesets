rule TTP_XOR_WriteProcessMemory_cc5a {
  strings:
    $key_cc5a = { 9b 28 [2] a9 0a [2] af 3f [2] 81 3f [2] be 23 }

  condition:
    any of them
}