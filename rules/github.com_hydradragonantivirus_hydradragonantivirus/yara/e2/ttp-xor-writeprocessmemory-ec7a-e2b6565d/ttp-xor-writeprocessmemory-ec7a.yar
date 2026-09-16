rule TTP_XOR_WriteProcessMemory_ec7a {
  strings:
    $key_ec7a = { bb 08 [2] 89 2a [2] 8f 1f [2] a1 1f [2] 9e 03 }

  condition:
    any of them
}