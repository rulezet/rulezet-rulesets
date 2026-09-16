rule TTP_XOR_WriteProcessMemory_e77a {
  strings:
    $key_e77a = { b0 08 [2] 82 2a [2] 84 1f [2] aa 1f [2] 95 03 }

  condition:
    any of them
}