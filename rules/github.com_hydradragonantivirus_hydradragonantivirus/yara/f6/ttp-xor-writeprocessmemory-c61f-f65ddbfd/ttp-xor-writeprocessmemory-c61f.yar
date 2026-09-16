rule TTP_XOR_WriteProcessMemory_c61f {
  strings:
    $key_c61f = { 91 6d [2] a3 4f [2] a5 7a [2] 8b 7a [2] b4 66 }

  condition:
    any of them
}