rule TTP_XOR_WriteProcessMemory_d501 {
  strings:
    $key_d501 = { 82 73 [2] b0 51 [2] b6 64 [2] 98 64 [2] a7 78 }

  condition:
    any of them
}