rule TTP_XOR_WriteProcessMemory_d001 {
  strings:
    $key_d001 = { 87 73 [2] b5 51 [2] b3 64 [2] 9d 64 [2] a2 78 }

  condition:
    any of them
}