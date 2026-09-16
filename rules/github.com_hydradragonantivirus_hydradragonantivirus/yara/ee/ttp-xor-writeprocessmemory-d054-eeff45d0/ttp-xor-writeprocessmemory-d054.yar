rule TTP_XOR_WriteProcessMemory_d054 {
  strings:
    $key_d054 = { 87 26 [2] b5 04 [2] b3 31 [2] 9d 31 [2] a2 2d }

  condition:
    any of them
}