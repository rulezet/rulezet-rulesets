rule TTP_XOR_WriteProcessMemory_d43f {
  strings:
    $key_d43f = { 83 4d [2] b1 6f [2] b7 5a [2] 99 5a [2] a6 46 }

  condition:
    any of them
}