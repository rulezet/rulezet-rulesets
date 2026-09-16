rule TTP_XOR_WriteProcessMemory_d00f {
  strings:
    $key_d00f = { 87 7d [2] b5 5f [2] b3 6a [2] 9d 6a [2] a2 76 }

  condition:
    any of them
}