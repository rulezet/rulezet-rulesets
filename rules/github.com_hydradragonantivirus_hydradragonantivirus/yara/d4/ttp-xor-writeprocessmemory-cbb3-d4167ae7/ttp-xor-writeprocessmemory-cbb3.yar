rule TTP_XOR_WriteProcessMemory_cbb3 {
  strings:
    $key_cbb3 = { 9c c1 [2] ae e3 [2] a8 d6 [2] 86 d6 [2] b9 ca }

  condition:
    any of them
}