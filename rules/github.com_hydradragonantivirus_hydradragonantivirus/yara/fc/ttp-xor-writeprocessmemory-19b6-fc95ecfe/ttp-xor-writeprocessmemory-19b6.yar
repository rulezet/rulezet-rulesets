rule TTP_XOR_WriteProcessMemory_19b6 {
  strings:
    $key_19b6 = { 4e c4 [2] 7c e6 [2] 7a d3 [2] 54 d3 [2] 6b cf }

  condition:
    any of them
}