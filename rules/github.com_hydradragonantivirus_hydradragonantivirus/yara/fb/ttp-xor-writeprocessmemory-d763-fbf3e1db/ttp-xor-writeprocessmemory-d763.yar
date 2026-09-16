rule TTP_XOR_WriteProcessMemory_d763 {
  strings:
    $key_d763 = { 80 11 [2] b2 33 [2] b4 06 [2] 9a 06 [2] a5 1a }

  condition:
    any of them
}