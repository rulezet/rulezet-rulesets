rule TTP_XOR_WriteProcessMemory_d76f {
  strings:
    $key_d76f = { 80 1d [2] b2 3f [2] b4 0a [2] 9a 0a [2] a5 16 }

  condition:
    any of them
}