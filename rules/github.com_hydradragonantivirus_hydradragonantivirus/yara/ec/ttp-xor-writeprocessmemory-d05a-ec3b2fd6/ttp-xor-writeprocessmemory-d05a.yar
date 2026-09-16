rule TTP_XOR_WriteProcessMemory_d05a {
  strings:
    $key_d05a = { 87 28 [2] b5 0a [2] b3 3f [2] 9d 3f [2] a2 23 }

  condition:
    any of them
}