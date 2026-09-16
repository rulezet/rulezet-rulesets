rule TTP_XOR_WriteProcessMemory_00b6 {
  strings:
    $key_00b6 = { 57 c4 [2] 65 e6 [2] 63 d3 [2] 4d d3 [2] 72 cf }

  condition:
    any of them
}