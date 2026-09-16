rule TTP_XOR_WriteProcessMemory_d14a {
  strings:
    $key_d14a = { 86 38 [2] b4 1a [2] b2 2f [2] 9c 2f [2] a3 33 }

  condition:
    any of them
}