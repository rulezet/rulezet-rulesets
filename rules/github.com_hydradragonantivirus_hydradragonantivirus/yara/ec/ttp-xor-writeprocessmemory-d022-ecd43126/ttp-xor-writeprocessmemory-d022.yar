rule TTP_XOR_WriteProcessMemory_d022 {
  strings:
    $key_d022 = { 87 50 [2] b5 72 [2] b3 47 [2] 9d 47 [2] a2 5b }

  condition:
    any of them
}