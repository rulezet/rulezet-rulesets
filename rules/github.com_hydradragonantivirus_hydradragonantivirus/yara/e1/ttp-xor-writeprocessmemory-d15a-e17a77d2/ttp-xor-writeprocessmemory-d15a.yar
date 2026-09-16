rule TTP_XOR_WriteProcessMemory_d15a {
  strings:
    $key_d15a = { 86 28 [2] b4 0a [2] b2 3f [2] 9c 3f [2] a3 23 }

  condition:
    any of them
}