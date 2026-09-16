rule TTP_XOR_WriteProcessMemory_d61a {
  strings:
    $key_d61a = { 81 68 [2] b3 4a [2] b5 7f [2] 9b 7f [2] a4 63 }

  condition:
    any of them
}