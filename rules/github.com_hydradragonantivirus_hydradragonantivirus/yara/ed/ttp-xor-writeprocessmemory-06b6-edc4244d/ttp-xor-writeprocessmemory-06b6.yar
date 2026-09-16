rule TTP_XOR_WriteProcessMemory_06b6 {
  strings:
    $key_06b6 = { 51 c4 [2] 63 e6 [2] 65 d3 [2] 4b d3 [2] 74 cf }

  condition:
    any of them
}