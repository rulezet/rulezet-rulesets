rule TTP_XOR_WriteProcessMemory_c03f {
  strings:
    $key_c03f = { 97 4d [2] a5 6f [2] a3 5a [2] 8d 5a [2] b2 46 }

  condition:
    any of them
}