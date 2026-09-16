rule TTP_XOR_WriteProcessMemory_ee83 {
  strings:
    $key_ee83 = { b9 f1 [2] 8b d3 [2] 8d e6 [2] a3 e6 [2] 9c fa }

  condition:
    any of them
}