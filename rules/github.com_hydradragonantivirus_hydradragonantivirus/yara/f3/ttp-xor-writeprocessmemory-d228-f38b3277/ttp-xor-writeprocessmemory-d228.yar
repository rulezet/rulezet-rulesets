rule TTP_XOR_WriteProcessMemory_d228 {
  strings:
    $key_d228 = { 85 5a [2] b7 78 [2] b1 4d [2] 9f 4d [2] a0 51 }

  condition:
    any of them
}