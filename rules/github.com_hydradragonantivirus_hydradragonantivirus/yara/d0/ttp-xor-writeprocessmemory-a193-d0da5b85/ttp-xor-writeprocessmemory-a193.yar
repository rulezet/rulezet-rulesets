rule TTP_XOR_WriteProcessMemory_a193 {
  strings:
    $key_a193 = { f6 e1 [2] c4 c3 [2] c2 f6 [2] ec f6 [2] d3 ea }

  condition:
    any of them
}