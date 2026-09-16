rule TTP_XOR_WriteProcessMemory_cd83 {
  strings:
    $key_cd83 = { 9a f1 [2] a8 d3 [2] ae e6 [2] 80 e6 [2] bf fa }

  condition:
    any of them
}