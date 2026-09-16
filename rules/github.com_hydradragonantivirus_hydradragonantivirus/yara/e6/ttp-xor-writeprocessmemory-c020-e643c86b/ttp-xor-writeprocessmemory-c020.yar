rule TTP_XOR_WriteProcessMemory_c020 {
  strings:
    $key_c020 = { 97 52 [2] a5 70 [2] a3 45 [2] 8d 45 [2] b2 59 }

  condition:
    any of them
}