rule TTP_XOR_WriteProcessMemory_d103 {
  strings:
    $key_d103 = { 86 71 [2] b4 53 [2] b2 66 [2] 9c 66 [2] a3 7a }

  condition:
    any of them
}