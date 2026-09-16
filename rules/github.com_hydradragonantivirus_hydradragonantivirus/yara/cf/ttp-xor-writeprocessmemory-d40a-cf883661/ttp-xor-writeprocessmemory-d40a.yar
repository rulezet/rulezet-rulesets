rule TTP_XOR_WriteProcessMemory_d40a {
  strings:
    $key_d40a = { 83 78 [2] b1 5a [2] b7 6f [2] 99 6f [2] a6 73 }

  condition:
    any of them
}