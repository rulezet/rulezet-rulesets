rule TTP_XOR_WriteProcessMemory_66b6 {
  strings:
    $key_66b6 = { 31 c4 [2] 03 e6 [2] 05 d3 [2] 2b d3 [2] 14 cf }

  condition:
    any of them
}