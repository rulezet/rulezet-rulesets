rule TTP_XOR_WriteProcessMemory_ed6a {
  strings:
    $key_ed6a = { ba 18 [2] 88 3a [2] 8e 0f [2] a0 0f [2] 9f 13 }

  condition:
    any of them
}