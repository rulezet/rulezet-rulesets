rule TTP_XOR_WriteProcessMemory_edb6 {
  strings:
    $key_edb6 = { ba c4 [2] 88 e6 [2] 8e d3 [2] a0 d3 [2] 9f cf }

  condition:
    any of them
}