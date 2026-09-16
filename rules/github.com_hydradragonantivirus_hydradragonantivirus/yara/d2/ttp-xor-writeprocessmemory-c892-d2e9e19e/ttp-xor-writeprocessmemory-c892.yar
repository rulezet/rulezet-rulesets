rule TTP_XOR_WriteProcessMemory_c892 {
  strings:
    $key_c892 = { 9f e0 [2] ad c2 [2] ab f7 [2] 85 f7 [2] ba eb }

  condition:
    any of them
}