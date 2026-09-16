rule TTP_XOR_WriteProcessMemory_eb1a {
  strings:
    $key_eb1a = { bc 68 [2] 8e 4a [2] 88 7f [2] a6 7f [2] 99 63 }

  condition:
    any of them
}