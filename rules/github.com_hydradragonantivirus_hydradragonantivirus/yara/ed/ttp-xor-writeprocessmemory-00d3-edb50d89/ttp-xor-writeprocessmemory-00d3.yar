rule TTP_XOR_WriteProcessMemory_00d3 {
  strings:
    $key_00d3 = { 57 a1 [2] 65 83 [2] 63 b6 [2] 4d b6 [2] 72 aa }

  condition:
    any of them
}