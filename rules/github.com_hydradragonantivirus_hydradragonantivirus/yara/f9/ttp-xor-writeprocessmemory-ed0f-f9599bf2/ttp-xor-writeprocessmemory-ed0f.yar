rule TTP_XOR_WriteProcessMemory_ed0f {
  strings:
    $key_ed0f = { ba 7d [2] 88 5f [2] 8e 6a [2] a0 6a [2] 9f 76 }

  condition:
    any of them
}