rule TTP_XOR_WriteProcessMemory_d0e8 {
  strings:
    $key_d0e8 = { 87 9a [2] b5 b8 [2] b3 8d [2] 9d 8d [2] a2 91 }

  condition:
    any of them
}