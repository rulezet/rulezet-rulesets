rule TTP_XOR_WriteProcessMemory_7ab6 {
  strings:
    $key_7ab6 = { 2d c4 [2] 1f e6 [2] 19 d3 [2] 37 d3 [2] 08 cf }

  condition:
    any of them
}