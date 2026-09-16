rule TTP_XOR_WriteProcessMemory_ec6a {
  strings:
    $key_ec6a = { bb 18 [2] 89 3a [2] 8f 0f [2] a1 0f [2] 9e 13 }

  condition:
    any of them
}