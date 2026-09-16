rule TTP_XOR_WriteProcessMemory_5ab6 {
  strings:
    $key_5ab6 = { 0d c4 [2] 3f e6 [2] 39 d3 [2] 17 d3 [2] 28 cf }

  condition:
    any of them
}