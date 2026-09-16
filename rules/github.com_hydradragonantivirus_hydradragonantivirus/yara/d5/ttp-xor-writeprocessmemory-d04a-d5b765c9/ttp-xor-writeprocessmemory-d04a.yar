rule TTP_XOR_WriteProcessMemory_d04a {
  strings:
    $key_d04a = { 87 38 [2] b5 1a [2] b3 2f [2] 9d 2f [2] a2 33 }

  condition:
    any of them
}