rule TTP_XOR_WriteProcessMemory_b0b5 {
  strings:
    $key_b0b5 = { e7 c7 [2] d5 e5 [2] d3 d0 [2] fd d0 [2] c2 cc }

  condition:
    any of them
}