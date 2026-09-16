rule TTP_XOR_WriteProcessMemory_c092 {
  strings:
    $key_c092 = { 97 e0 [2] a5 c2 [2] a3 f7 [2] 8d f7 [2] b2 eb }

  condition:
    any of them
}