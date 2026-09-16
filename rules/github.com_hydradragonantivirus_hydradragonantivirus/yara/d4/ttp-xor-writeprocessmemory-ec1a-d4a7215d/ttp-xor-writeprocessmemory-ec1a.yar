rule TTP_XOR_WriteProcessMemory_ec1a {
  strings:
    $key_ec1a = { bb 68 [2] 89 4a [2] 8f 7f [2] a1 7f [2] 9e 63 }

  condition:
    any of them
}