rule TTP_XOR_WriteProcessMemory_d138 {
  strings:
    $key_d138 = { 86 4a [2] b4 68 [2] b2 5d [2] 9c 5d [2] a3 41 }

  condition:
    any of them
}