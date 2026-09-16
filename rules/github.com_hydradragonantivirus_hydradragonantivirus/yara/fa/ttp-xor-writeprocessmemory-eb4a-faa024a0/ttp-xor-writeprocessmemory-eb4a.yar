rule TTP_XOR_WriteProcessMemory_eb4a {
  strings:
    $key_eb4a = { bc 38 [2] 8e 1a [2] 88 2f [2] a6 2f [2] 99 33 }

  condition:
    any of them
}