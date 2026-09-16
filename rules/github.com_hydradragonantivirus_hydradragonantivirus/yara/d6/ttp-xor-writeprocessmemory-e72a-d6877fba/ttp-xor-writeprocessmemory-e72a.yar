rule TTP_XOR_WriteProcessMemory_e72a {
  strings:
    $key_e72a = { b0 58 [2] 82 7a [2] 84 4f [2] aa 4f [2] 95 53 }

  condition:
    any of them
}