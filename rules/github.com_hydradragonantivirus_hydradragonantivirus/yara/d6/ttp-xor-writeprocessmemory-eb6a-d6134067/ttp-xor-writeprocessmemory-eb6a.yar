rule TTP_XOR_WriteProcessMemory_eb6a {
  strings:
    $key_eb6a = { bc 18 [2] 8e 3a [2] 88 0f [2] a6 0f [2] 99 13 }

  condition:
    any of them
}