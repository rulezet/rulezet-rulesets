rule TTP_XOR_WriteProcessMemory_ceb6 {
  strings:
    $key_ceb6 = { 99 c4 [2] ab e6 [2] ad d3 [2] 83 d3 [2] bc cf }

  condition:
    any of them
}