rule TTP_XOR_WriteProcessMemory_ed1f {
  strings:
    $key_ed1f = { ba 6d [2] 88 4f [2] 8e 7a [2] a0 7a [2] 9f 66 }

  condition:
    any of them
}