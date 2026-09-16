rule TTP_XOR_WriteProcessMemory_d192 {
  strings:
    $key_d192 = { 86 e0 [2] b4 c2 [2] b2 f7 [2] 9c f7 [2] a3 eb }

  condition:
    any of them
}