rule TTP_XOR_WriteProcessMemory_f980 {
  strings:
    $key_f980 = { ae f2 [2] 9c d0 [2] 9a e5 [2] b4 e5 [2] 8b f9 }

  condition:
    any of them
}