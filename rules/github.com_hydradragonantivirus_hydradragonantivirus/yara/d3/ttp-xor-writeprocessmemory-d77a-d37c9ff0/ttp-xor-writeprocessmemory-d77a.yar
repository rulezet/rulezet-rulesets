rule TTP_XOR_WriteProcessMemory_d77a {
  strings:
    $key_d77a = { 80 08 [2] b2 2a [2] b4 1f [2] 9a 1f [2] a5 03 }

  condition:
    any of them
}