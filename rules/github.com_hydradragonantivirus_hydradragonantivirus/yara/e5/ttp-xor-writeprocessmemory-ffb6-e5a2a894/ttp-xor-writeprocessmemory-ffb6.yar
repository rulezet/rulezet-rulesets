rule TTP_XOR_WriteProcessMemory_ffb6 {
  strings:
    $key_ffb6 = { a8 c4 [2] 9a e6 [2] 9c d3 [2] b2 d3 [2] 8d cf }

  condition:
    any of them
}