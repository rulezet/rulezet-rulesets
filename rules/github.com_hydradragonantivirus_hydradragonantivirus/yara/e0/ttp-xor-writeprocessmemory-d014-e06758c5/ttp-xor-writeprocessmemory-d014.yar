rule TTP_XOR_WriteProcessMemory_d014 {
  strings:
    $key_d014 = { 87 66 [2] b5 44 [2] b3 71 [2] 9d 71 [2] a2 6d }

  condition:
    any of them
}