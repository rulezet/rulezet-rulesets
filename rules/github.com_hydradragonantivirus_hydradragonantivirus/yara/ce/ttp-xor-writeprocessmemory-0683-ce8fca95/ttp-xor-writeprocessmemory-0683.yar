rule TTP_XOR_WriteProcessMemory_0683 {
  strings:
    $key_0683 = { 51 f1 [2] 63 d3 [2] 65 e6 [2] 4b e6 [2] 74 fa }

  condition:
    any of them
}