rule TTP_XOR_WriteProcessMemory_c42f {
  strings:
    $key_c42f = { 93 5d [2] a1 7f [2] a7 4a [2] 89 4a [2] b6 56 }

  condition:
    any of them
}