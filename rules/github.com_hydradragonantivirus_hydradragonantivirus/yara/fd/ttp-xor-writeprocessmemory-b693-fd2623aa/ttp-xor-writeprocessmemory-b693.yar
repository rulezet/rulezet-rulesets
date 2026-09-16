rule TTP_XOR_WriteProcessMemory_b693 {
  strings:
    $key_b693 = { e1 e1 [2] d3 c3 [2] d5 f6 [2] fb f6 [2] c4 ea }

  condition:
    any of them
}