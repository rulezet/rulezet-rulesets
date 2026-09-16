rule TTP_XOR_WriteProcessMemory_d10a {
  strings:
    $key_d10a = { 86 78 [2] b4 5a [2] b2 6f [2] 9c 6f [2] a3 73 }

  condition:
    any of them
}