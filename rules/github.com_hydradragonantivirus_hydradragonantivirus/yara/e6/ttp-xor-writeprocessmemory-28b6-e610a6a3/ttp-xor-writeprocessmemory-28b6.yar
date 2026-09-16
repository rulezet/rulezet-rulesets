rule TTP_XOR_WriteProcessMemory_28b6 {
  strings:
    $key_28b6 = { 7f c4 [2] 4d e6 [2] 4b d3 [2] 65 d3 [2] 5a cf }

  condition:
    any of them
}