rule TTP_XOR_WriteProcessMemory_c47f {
  strings:
    $key_c47f = { 93 0d [2] a1 2f [2] a7 1a [2] 89 1a [2] b6 06 }

  condition:
    any of them
}