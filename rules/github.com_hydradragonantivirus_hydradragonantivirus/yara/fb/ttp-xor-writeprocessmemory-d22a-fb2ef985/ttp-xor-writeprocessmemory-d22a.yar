rule TTP_XOR_WriteProcessMemory_d22a {
  strings:
    $key_d22a = { 85 58 [2] b7 7a [2] b1 4f [2] 9f 4f [2] a0 53 }

  condition:
    any of them
}