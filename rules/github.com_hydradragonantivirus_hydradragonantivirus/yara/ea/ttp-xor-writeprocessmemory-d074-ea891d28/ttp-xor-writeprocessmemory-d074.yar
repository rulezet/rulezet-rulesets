rule TTP_XOR_WriteProcessMemory_d074 {
  strings:
    $key_d074 = { 87 06 [2] b5 24 [2] b3 11 [2] 9d 11 [2] a2 0d }

  condition:
    any of them
}